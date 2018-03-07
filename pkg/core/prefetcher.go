package core

import (
	"context"
	"sync"
	"time"

	"github.com/ash2k/iam4kube"
	"github.com/ash2k/iam4kube/pkg/util/logz"

	"github.com/ash2k/stager"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"k8s.io/client-go/util/buffer"
)

const (
	freshnessThresholdForGet           = 5 * time.Minute
	freshnessThresholdForPeriodicCheck = 3 * freshnessThresholdForGet // check in advance, before get would block
	freshnessCheckPeriod               = 1 * time.Minute
)

type Limiter interface {
	// Wait blocks until limiter permits an event to happen.
	// It returns an error if the Context is
	// canceled, or the expected wait time exceeds the Context's Deadline.
	Wait(context.Context) error
	// Burst returns the maximum burst size. Higher Burst values allow more events to happen at once.
	Burst() int
}

type credentialsPrefetcher struct {
	logger       *zap.Logger
	kloud        Kloud
	limiter      Limiter
	cache        map[iamRoleKey]cacheEntry
	toRefresh    chan iam4kube.IamRole
	toRefreshBuf buffer.RingGrowing
	refreshed    chan refreshedCreds
	get          chan credRequest
	cancel       chan credRequestCancel
	add          chan addRequest
	remove       chan removeRequest
}

func NewCredentialsPrefetcher(logger *zap.Logger, kloud Kloud, limiter Limiter) *credentialsPrefetcher {
	return &credentialsPrefetcher{
		logger:       logger,
		kloud:        kloud,
		limiter:      limiter,
		cache:        make(map[iamRoleKey]cacheEntry),
		toRefresh:    make(chan iam4kube.IamRole),
		toRefreshBuf: *buffer.NewRingGrowing(512), // holds iam roles to retrieve creds for
		refreshed:    make(chan refreshedCreds),
		get:          make(chan credRequest),
		cancel:       make(chan credRequestCancel),
		add:          make(chan addRequest),
		remove:       make(chan removeRequest),
	}
}

func (k *credentialsPrefetcher) Run(ctx context.Context) {
	var exitErr error
	defer func() {
		k.unblockAwaiting(exitErr)
	}()

	// Start workers
	stgr := stager.New()
	defer stgr.Shutdown()    // Tell workers to stop via context and wait for them
	defer close(k.toRefresh) // Tell workers to stop via channel

	stage := stgr.NextStage()
	for i := 0; i < k.limiter.Burst(); i++ {
		stage.StartWithContext(k.worker)
	}

	// Main loop

	var (
		toRefreshChan chan iam4kube.IamRole
		toRefreshRole iam4kube.IamRole
	)
	freshnessCheckTicker := time.NewTicker(freshnessCheckPeriod)
	defer freshnessCheckTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			exitErr = ctx.Err()
			return
		case <-freshnessCheckTicker.C:
			k.freshnessCheck()
		case toRefreshChan <- toRefreshRole: // disabled when toRefreshChan == nil
			toRefreshRole = iam4kube.IamRole{} // help GC
			toRefreshChan = nil                // disable this case
		case refreshed := <-k.refreshed:
			k.handleRefreshed(refreshed)
		case get := <-k.get:
			k.handleGet(get)
		case cancel := <-k.cancel:
			k.handleCancel(cancel)
		case add := <-k.add:
			k.handleAdd(add)
		case remove := <-k.remove:
			k.handleRemove(remove)
		}
		if toRefreshChan == nil {
			roleToRefresh, ok := k.toRefreshBuf.ReadOne()
			if ok {
				// There is an iam role that needs a refresh
				toRefreshRole = roleToRefresh.(iam4kube.IamRole)
				toRefreshChan = k.toRefresh
			}
		}
	}
}

func (k *credentialsPrefetcher) unblockAwaiting(err error) {
	if err == nil {
		err = errors.New("unexpected prefetcher exit. panic?")
	} else {
		err = errors.Wrap(err, "prefetcher exit")
	}
	for _, entry := range k.cache {
		for c := range entry.awaiting {
			c <- credResponse{
				err: err,
			}
		}
	}
}

// freshnessCheck checks cached credentials for freshness and enqueues them for refresh if necessary.
func (k *credentialsPrefetcher) freshnessCheck() {
	for _, entry := range k.cache {
		if entry.hasCreds && !entry.scheduledForRefresh && !entry.creds.WillBeValidForAtLeast(freshnessThresholdForPeriodicCheck) {
			k.toRefreshBuf.WriteOne(entry.role)
		}
	}
}

func (k *credentialsPrefetcher) handleRefreshed(creds refreshedCreds) {
	key := keyForRole(creds.role)
	entry, ok := k.cache[key]
	if !ok {
		// Such IAM role is not known, has been removed from cache
		return
	}
	if len(entry.awaiting) > 0 {
		// Send creds to awaiting callers
		for c := range entry.awaiting {
			c <- credResponse{
				creds: creds.creds,
			}
		}
		// Reset
		entry.awaiting = make(map[chan<- credResponse]struct{})
	}
	entry.creds = creds.creds
	entry.hasCreds = true
	entry.scheduledForRefresh = false
	k.cache[key] = entry
}

func (k *credentialsPrefetcher) handleGet(get credRequest) {
	key := keyForRole(get.role)
	entry, ok := k.cache[key]
	if !ok {
		// Such IAM role is not known
		get.result <- credResponse{
			err: errors.New("unknown IAM role"),
		}
		return
	}
	// Entry found in cache, check if it has credentials
	if entry.hasCreds && entry.creds.WillBeValidForAtLeast(freshnessThresholdForGet) {
		// Fresh enough creds found in the cache, return
		get.result <- credResponse{
			creds: entry.creds,
		}
		return
	}
	if !entry.scheduledForRefresh {
		// Creds have expired or will expire soon, request a refresh
		k.toRefreshBuf.WriteOne(get.role)
		entry.scheduledForRefresh = true
	}
	// Line up in the queue.
	entry.awaiting[get.result] = struct{}{}
}

func (k *credentialsPrefetcher) handleCancel(cancel credRequestCancel) {
	key := keyForRole(cancel.role)
	entry, ok := k.cache[key]
	if !ok {
		// This should not happen
		k.logger.Error("Unknown IAM role", logz.RoleArn(cancel.role.Arn))
		return
	}
	delete(entry.awaiting, cancel.result)
}

func (k *credentialsPrefetcher) handleAdd(add addRequest) {
	defer add.processed()
	key := keyForRole(add.role)
	if entry, ok := k.cache[key]; ok {
		// Role is known already, just increment the ref counter
		entry.refCounter++
		k.cache[key] = entry
		return
	}
	// Role is not known
	k.cache[key] = cacheEntry{
		role:                add.role,
		refCounter:          1,
		awaiting:            make(map[chan<- credResponse]struct{}),
		scheduledForRefresh: true,
	}
	k.toRefreshBuf.WriteOne(add.role)
}

func (k *credentialsPrefetcher) handleRemove(remove removeRequest) {
	defer remove.processed()
	key := keyForRole(remove.role)
	entry, ok := k.cache[key]
	if !ok {
		// Unknown role, this should not happen
		k.logger.Error("Unknown IAM role", logz.RoleArn(remove.role.Arn))
		return
	}
	// Role is known, decrement the ref counter
	entry.refCounter--
	if entry.refCounter > 0 {
		// There are still references to this role out there
		k.cache[key] = entry
		return
	}
	// No references, can drop from cache
	delete(k.cache, key)
	// Tell every awaiting client
	err := errors.New("IAM role was removed")
	for c := range entry.awaiting {
		c <- credResponse{
			err: err,
		}
	}
}

// CredentialsForRole fetches credentials from the cache.
// It blocks until credentials are available or the context signals done.
func (k *credentialsPrefetcher) CredentialsForRole(ctx context.Context, role *iam4kube.IamRole) (*iam4kube.Credentials, error) {
	result := make(chan credResponse)
	req := credRequest{
		role:   *role,
		result: result,
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case k.get <- req:
	}
	var resp credResponse
	select {
	case <-ctx.Done():
		cancel := credRequestCancel{
			role:   *role,
			result: result,
		}
		select {
		case k.cancel <- cancel:
			// Told main loop to cancel the lookup
			return nil, ctx.Err()
		case resp = <-result:
			// Got creds from main loop
		}
	case resp = <-result:
		// Got creds from main loop
	}
	if resp.err != nil {
		return nil, resp.err
	}
	return &resp.creds, nil

}

func (k *credentialsPrefetcher) Add(role *iam4kube.IamRole) {
	var wg sync.WaitGroup
	wg.Add(1)
	k.add <- addRequest{
		role:      *role,
		processed: wg.Done,
	}
	wg.Wait()
}

func (k *credentialsPrefetcher) Remove(role *iam4kube.IamRole) {
	var wg sync.WaitGroup
	wg.Add(1)
	k.remove <- removeRequest{
		role:      *role,
		processed: wg.Done,
	}
	wg.Wait()
}

// worker fetches credentials for roles it picks up from the channel.
// Results are pushed into the refreshed channel.
func (k *credentialsPrefetcher) worker(ctx context.Context) {
	for roleToRefresh := range k.toRefresh {
		if !k.workerRefreshRole(ctx, roleToRefresh) {
			break
		}
	}
}

func (k *credentialsPrefetcher) workerRefreshRole(ctx context.Context, role iam4kube.IamRole) bool {
	for {
		if err := k.limiter.Wait(ctx); err != nil {
			if err != context.DeadlineExceeded && err != context.Canceled {
				k.logger.Error("Unexpected error from rate limiter", logz.RoleArn(role.Arn), zap.Error(err))
			}
			return false
		}
		creds, err := k.kloud.CredentialsForRole(ctx, &role)
		if err != nil {
			cause := errors.Cause(err)
			if cause == context.DeadlineExceeded || cause == context.Canceled {
				// Time to stop
				return false
			}
			k.logger.Warn("Failed to fetch credentials for IAM role", logz.RoleArn(role.Arn), zap.Error(err))
			continue
		}
		refreshed := refreshedCreds{
			role:  role,
			creds: *creds,
		}
		select {
		case <-ctx.Done():
			return false
		case k.refreshed <- refreshed:
		}
		return true
	}
}

func keyForRole(role iam4kube.IamRole) iamRoleKey {
	key := iamRoleKey{
		arn: role.Arn,
	}
	if role.ExternalID == nil {
		key.idIsNotSet = true
	} else {
		key.externalID = *role.ExternalID
	}
	return key
}

type cacheEntry struct {
	role                iam4kube.IamRole
	creds               iam4kube.Credentials
	refCounter          int // holds the number of times Add() was called for the corresponding iam role
	awaiting            map[chan<- credResponse]struct{}
	hasCreds            bool // initially false, set to true when creds are retrieved for the first time
	scheduledForRefresh bool // true if creds are scheduled to be refreshed
}

type iamRoleKey struct {
	arn arn.ARN
	// Cannot use a pointer because pointers to equal strings may be not equal.
	externalID string
	// Set to true if externalID is not set.
	// This is to distinguish from the case when it is set to an empty string.
	idIsNotSet bool
}

type refreshedCreds struct {
	role  iam4kube.IamRole
	creds iam4kube.Credentials
}

type credRequest struct {
	role   iam4kube.IamRole
	result chan<- credResponse
}

type credRequestCancel struct {
	role   iam4kube.IamRole
	result chan<- credResponse
}

type credResponse struct {
	creds iam4kube.Credentials
	err   error
}

type addRequest struct {
	role      iam4kube.IamRole
	processed func()
}

type removeRequest struct {
	role      iam4kube.IamRole
	processed func()
}
