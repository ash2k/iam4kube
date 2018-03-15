package core

import (
	"context"
	"time"

	"github.com/ash2k/iam4kube"
	"github.com/ash2k/iam4kube/pkg/util/logz"
	"github.com/ash2k/stager"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
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
	logger               *zap.Logger
	kloud                Kloud
	limiter              Limiter
	cache                map[iamRoleKey]cacheEntry
	cacheSize            prometheus.Gauge
	toRefresh            chan iam4kube.IamRole
	toRefreshBuf         buffer.RingGrowing
	toRefreshBufLength   prometheus.Gauge
	refreshed            chan refreshedCreds
	get                  chan credRequest
	cancel               chan credRequestCancel
	add                  chan addRequest
	remove               chan removeRequest
	addCount             prometheus.Counter
	removeCount          prometheus.Counter
	getCredsSuccessCount prometheus.Counter
	getCredsErrorCount   prometheus.Counter
	busyWorkersNumber    prometheus.Gauge
}

func NewCredentialsPrefetcher(logger *zap.Logger, kloud Kloud, registry prometheus.Registerer, limiter Limiter) (*credentialsPrefetcher, error) {
	addCount := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "iam4kube",
		Subsystem: "prefetcher",
		Name:      "add_role_count",
		Help:      "Number of times a role was added",
	})
	removeCount := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "iam4kube",
		Subsystem: "prefetcher",
		Name:      "remove_role_count",
		Help:      "Number of times a role was removed",
	})
	getCredsSuccessCount := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "iam4kube",
		Subsystem: "prefetcher",
		Name:      "get_creds_success_count",
		Help:      "Number of times credentials were successfully fetched from STS",
	})
	getCredsErrorCount := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "iam4kube",
		Subsystem: "prefetcher",
		Name:      "get_creds_error_count",
		Help:      "Number of times credentials prefetch failed",
	})
	cacheSize := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "iam4kube",
		Subsystem: "prefetcher",
		Name:      "cache_size",
		Help:      "Number of items in the cache",
	})
	toRefreshBufLength := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "iam4kube",
		Subsystem: "prefetcher",
		Name:      "to_refresh_buffer_length",
		Help:      "Length of the queue with credentials to refresh/fetch",
	})
	busyWorkersNumber := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "iam4kube",
		Subsystem: "prefetcher",
		Name:      "busy_workers_number",
		Help:      "Number of workers that are busy fetching credentials",
	})
	allMetrics := []prometheus.Collector{
		addCount, removeCount,
		getCredsSuccessCount, getCredsErrorCount,
		cacheSize, toRefreshBufLength, busyWorkersNumber,
	}
	for _, metric := range allMetrics {
		if err := registry.Register(metric); err != nil {
			return nil, errors.WithStack(err)
		}
	}
	return &credentialsPrefetcher{
		logger:               logger,
		kloud:                kloud,
		limiter:              limiter,
		cache:                make(map[iamRoleKey]cacheEntry),
		cacheSize:            cacheSize,
		toRefresh:            make(chan iam4kube.IamRole),
		toRefreshBuf:         *buffer.NewRingGrowing(512), // holds iam roles to retrieve creds for
		toRefreshBufLength:   toRefreshBufLength,
		refreshed:            make(chan refreshedCreds),
		get:                  make(chan credRequest),
		cancel:               make(chan credRequestCancel),
		add:                  make(chan addRequest),
		remove:               make(chan removeRequest),
		addCount:             addCount,
		removeCount:          removeCount,
		getCredsSuccessCount: getCredsSuccessCount,
		getCredsErrorCount:   getCredsErrorCount,
		busyWorkersNumber:    busyWorkersNumber,
	}, nil
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
				k.toRefreshBufLength.Dec()
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
	for key, entry := range k.cache {
		if entry.hasCreds && !entry.enqueuedForRefresh && !entry.creds.WillBeValidForAtLeast(freshnessThresholdForPeriodicCheck) {
			k.enqueueForRefresh(&entry)
			k.cache[key] = entry
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
	entry.enqueuedForRefresh = false
	k.cache[key] = entry
}

func (k *credentialsPrefetcher) handleGet(get credRequest) {
	key := keyForRole(get.role)
	entry, ok := k.cache[key]
	if !ok {
		// Such IAM role is not known
		k.cache[key] = cacheEntry{
			role:              get.role,
			timesAddedCounter: 0, // 0 means someone wants credentials for this role but it hasn't been added yet
			awaiting: map[chan<- credResponse]struct{}{
				get.result: {},
			},
			enqueuedForRefresh: false, // not scheduling for refresh because it has not been added
		}
		k.cacheSize.Set(float64(len(k.cache)))
		return
	}
	// Entry found in cache, check if it has been added
	if entry.timesAddedCounter > 0 {
		// Role has been added, check creds
		if entry.hasCreds && entry.creds.WillBeValidForAtLeast(freshnessThresholdForGet) {
			// Fresh enough creds found in the cache, return
			get.result <- credResponse{
				creds: entry.creds,
			}
			return
		}
		// Creds have expired or will expire soon
		if !entry.enqueuedForRefresh {
			// Request a refresh if not enqueued already
			k.enqueueForRefresh(&entry)
			k.cache[key] = entry
		}
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
	key := keyForRole(add.role)
	if entry, ok := k.cache[key]; ok {
		// Role has an entry already
		if entry.timesAddedCounter == 0 {
			// Entry is there but role hasn't been added before.
			// That means creds were requested before role was added.
			// Enqueue for refresh.
			k.enqueueForRefresh(&entry)
		}
		entry.timesAddedCounter++ // increment the counter
		k.cache[key] = entry
		return
	}
	// Role does not have an entry
	entry := cacheEntry{
		role:               add.role,
		timesAddedCounter:  1,
		awaiting:           make(map[chan<- credResponse]struct{}),
		enqueuedForRefresh: true,
	}
	k.enqueueForRefresh(&entry)
	k.cache[key] = entry
	k.cacheSize.Set(float64(len(k.cache)))
}

func (k *credentialsPrefetcher) handleRemove(remove removeRequest) {
	key := keyForRole(remove.role)
	entry, ok := k.cache[key]
	if !ok {
		// Unknown role, this should not happen
		k.logger.Error("Unknown IAM role", logz.RoleArn(remove.role.Arn))
		return
	}
	// Role is known, decrement the ref counter
	entry.timesAddedCounter--
	if entry.timesAddedCounter > 0 {
		// There are still references to this role out there
		k.cache[key] = entry
		return
	}
	// No references, can drop from cache
	delete(k.cache, key)
	k.cacheSize.Set(float64(len(k.cache)))
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
	k.addCount.Inc()
	k.add <- addRequest{
		role: *role,
	}
}

func (k *credentialsPrefetcher) Remove(role *iam4kube.IamRole) {
	k.removeCount.Inc()
	k.remove <- removeRequest{
		role: *role,
	}
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
	k.busyWorkersNumber.Inc()
	defer k.busyWorkersNumber.Dec()
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
			k.getCredsErrorCount.Inc()
			k.logger.Warn("Failed to fetch credentials for IAM role", logz.RoleArn(role.Arn), zap.Error(err))
			continue
		}
		k.getCredsSuccessCount.Inc()
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

func (k *credentialsPrefetcher) enqueueForRefresh(entry *cacheEntry) {
	k.toRefreshBuf.WriteOne(entry.role)
	k.toRefreshBufLength.Inc()
	entry.enqueuedForRefresh = true
}

func keyForRole(role iam4kube.IamRole) iamRoleKey {
	key := iamRoleKey{
		arn:         role.Arn,
		sessionName: role.SessionName,
	}
	if role.ExternalID == nil {
		key.idIsNotSet = true
	} else {
		key.externalID = *role.ExternalID
	}
	return key
}

type cacheEntry struct {
	role               iam4kube.IamRole
	creds              iam4kube.Credentials
	timesAddedCounter  int // holds the number of times Add() was called for the corresponding iam role
	awaiting           map[chan<- credResponse]struct{}
	hasCreds           bool // initially false, set to true when creds are retrieved for the first time
	enqueuedForRefresh bool // true if creds are scheduled to be refreshed
}

type iamRoleKey struct {
	arn         arn.ARN
	sessionName string
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
	role iam4kube.IamRole
}

type removeRequest struct {
	role iam4kube.IamRole
}
