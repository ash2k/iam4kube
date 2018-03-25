package core

import (
	"context"
	"fmt"
	"sync/atomic"
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
	defaultFreshnessCheckPeriod        = 1 * time.Minute
)

type Limiter interface {
	// Wait blocks until limiter permits an event to happen.
	// It returns an error if the Context is
	// canceled, or the expected wait time exceeds the Context's Deadline.
	Wait(context.Context) error
}

type Metrics struct {
	BusyWorkersNumber  int32
	ToRefreshBufLength int32
}

type CredentialsPrefetcher struct {
	logger               *zap.Logger
	kloud                Kloud
	limiter              Limiter
	workers              int
	freshnessCheckPeriod time.Duration
	cache                map[IamRoleKey]CacheEntry
	cacheSize            prometheus.Gauge
	toRefresh            chan iam4kube.IamRole
	toRefreshBuf         buffer.RingGrowing
	toRefreshBufLength   int32 // atomic access only
	refreshed            chan refreshedCreds
	get                  chan credRequest
	cancel               chan credRequestCancel
	add                  chan addRequest
	remove               chan removeRequest
	inspect              chan func(map[IamRoleKey]CacheEntry)
	addCount             prometheus.Counter
	removeCount          prometheus.Counter
	getCredsSuccessCount prometheus.Counter
	getCredsErrorCount   prometheus.Counter
	busyWorkersNumber    int32 // atomic access only
	refreshAttemptsTotal prometheus.Counter
}

func NewCredentialsPrefetcher(logger *zap.Logger, kloud Kloud, registry prometheus.Registerer,
	limiter Limiter, workers int) (*CredentialsPrefetcher, error) {
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
	refreshAttemptsTotal := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "iam4kube",
		Subsystem: "prefetcher",
		Name:      "refresh_attempts_total",
		Help:      "Number of attempts to refresh/fetch credentials",
	})
	prefetcher := &CredentialsPrefetcher{
		logger:               logger,
		kloud:                kloud,
		limiter:              limiter,
		workers:              workers,
		freshnessCheckPeriod: defaultFreshnessCheckPeriod,
		cache:                make(map[IamRoleKey]CacheEntry),
		cacheSize:            cacheSize,
		toRefresh:            make(chan iam4kube.IamRole),
		toRefreshBuf:         *buffer.NewRingGrowing(512), // holds roles to retrieve creds for
		refreshed:            make(chan refreshedCreds),
		get:                  make(chan credRequest),
		cancel:               make(chan credRequestCancel),
		add:                  make(chan addRequest),
		remove:               make(chan removeRequest),
		inspect:              make(chan func(map[IamRoleKey]CacheEntry)),
		addCount:             addCount,
		removeCount:          removeCount,
		getCredsSuccessCount: getCredsSuccessCount,
		getCredsErrorCount:   getCredsErrorCount,
		refreshAttemptsTotal: refreshAttemptsTotal,
	}
	toRefreshBufLength := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: "iam4kube",
		Subsystem: "prefetcher",
		Name:      "to_refresh_buffer_length",
		Help:      "Length of the queue with credentials to refresh/fetch",
	}, gaugeFuncForInt32(&prefetcher.toRefreshBufLength))
	busyWorkersNumber := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: "iam4kube",
		Subsystem: "prefetcher",
		Name:      "busy_workers_number",
		Help:      "Number of workers that are busy fetching credentials",
	}, gaugeFuncForInt32(&prefetcher.busyWorkersNumber))
	allMetrics := []prometheus.Collector{
		addCount, removeCount,
		getCredsSuccessCount, getCredsErrorCount,
		cacheSize, toRefreshBufLength, refreshAttemptsTotal, busyWorkersNumber,
	}
	for _, metric := range allMetrics {
		if err := registry.Register(metric); err != nil {
			return nil, errors.WithStack(err)
		}
	}

	return prefetcher, nil
}

func (k *CredentialsPrefetcher) Run(ctx context.Context) {
	var exitErr error
	defer func() {
		k.unblockAwaiting(exitErr)
	}()

	// Start workers
	stgr := stager.New()
	defer stgr.Shutdown()    // Tell workers to stop via context and wait for them
	defer close(k.toRefresh) // Tell workers to stop via channel

	stage := stgr.NextStage()
	for i := 0; i < k.workers; i++ {
		stage.StartWithContext(k.worker)
	}

	// Main loop

	var (
		toRefreshChan chan<- iam4kube.IamRole
		toRefreshRole iam4kube.IamRole
	)
	freshnessCheckTicker := time.NewTicker(k.freshnessCheckPeriod)
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
		case inspectFunc := <-k.inspect:
			inspectFunc(k.cache)
		}
		if toRefreshChan == nil {
			roleToRefresh, ok := k.toRefreshBuf.ReadOne()
			if ok {
				atomic.AddInt32(&k.toRefreshBufLength, -1)
				// There is an role that needs a refresh
				toRefreshRole = roleToRefresh.(iam4kube.IamRole)
				toRefreshChan = k.toRefresh
			}
		}
	}
}

func (k *CredentialsPrefetcher) unblockAwaiting(err error) {
	if err == nil {
		err = errors.New("unexpected prefetcher exit. panic?")
	} else {
		err = errors.Wrap(err, "prefetcher exit")
	}
	for _, entry := range k.cache {
		for c := range entry.Awaiting {
			c <- credResponse{
				err: err,
			}
		}
	}
}

// freshnessCheck checks cached credentials for freshness and enqueues them for refresh if necessary.
func (k *CredentialsPrefetcher) freshnessCheck() {
	for key, entry := range k.cache {
		if entry.HasCreds && !entry.EnqueuedForRefresh && !entry.Creds.WillBeValidForAtLeast(freshnessThresholdForPeriodicCheck) {
			k.enqueueForRefresh(&entry)
			k.cache[key] = entry
		}
	}
}

func (k *CredentialsPrefetcher) handleRefreshed(creds refreshedCreds) {
	logger := k.logger.With(logz.RoleArn(creds.role.Arn), logz.RoleSessionName(creds.role.SessionName))
	logger.Debug("Handling refreshed creds")
	key := keyForRole(creds.role)
	entry, ok := k.cache[key]
	if !ok {
		// Such role is not known, has been removed from cache
		logger.Debug("Unknown role")
		return
	}
	if entry.TimesAddedCounter == 0 {
		// race between add/remove and credentials refresh:
		// 1. add() adds entry and schedules refersh
		// 2. refresh started
		// 3. remove() removes entry
		// 4. get() creates a dummy entry because role wasn't added after it's been removed
		// 5. refresh finishes and must not send creds to the waiters even though there is a dummy entry
		k.logger.Sugar().Debugf("Role has a dummy entry but hasn't been added - not sending creds to %d awaiting callers", len(entry.Awaiting))
		return
	}
	if len(entry.Awaiting) > 0 {
		// Send creds to awaiting callers
		logger.Sugar().Debugf("Sending refreshed creds to %d awaiting callers", len(entry.Awaiting))
		for c := range entry.Awaiting {
			c <- credResponse{
				creds: creds.creds,
			}
		}
		// Reset
		entry.Awaiting = make(map[chan<- credResponse]struct{})
	}
	entry.Creds = creds.creds
	entry.HasCreds = true
	entry.EnqueuedForRefresh = false
	k.cache[key] = entry
}

func (k *CredentialsPrefetcher) handleGet(get credRequest) {
	logger := k.logger.With(logz.RoleArn(get.role.Arn), logz.RoleSessionName(get.role.SessionName))
	logger.Debug("Handling credentials request")
	key := keyForRole(get.role)
	entry, ok := k.cache[key]
	if !ok {
		// Such role is not known
		logger.Debug("Unknown role, creating dummy entry in the cache")
		k.cache[key] = CacheEntry{
			Role:              get.role,
			TimesAddedCounter: 0, // 0 means someone wants credentials for this role but it hasn't been added yet
			Awaiting: map[chan<- credResponse]struct{}{
				get.result: {},
			},
			EnqueuedForRefresh: false, // not scheduling for refresh because it has not been added
		}
		k.cacheSize.Set(float64(len(k.cache)))
		return
	}
	// Entry found in cache, check if it has been added
	if entry.TimesAddedCounter > 0 {
		// Role has been added, check creds
		if entry.HasCreds && entry.Creds.WillBeValidForAtLeast(freshnessThresholdForGet) {
			// Fresh enough creds found in the cache, return
			get.result <- credResponse{
				creds: entry.Creds,
			}
			return
		}
		// Creds have expired or will expire soon
		if !entry.EnqueuedForRefresh {
			// Request a refresh if not enqueued already
			k.enqueueForRefresh(&entry)
			k.cache[key] = entry
		}
	}
	// Line up in the queue.
	entry.Awaiting[get.result] = struct{}{}
}

func (k *CredentialsPrefetcher) handleCancel(cancel credRequestCancel) {
	logger := k.logger.With(logz.RoleArn(cancel.role.Arn), logz.RoleSessionName(cancel.role.SessionName))
	logger.Debug("Handling cancel request")
	key := keyForRole(cancel.role)
	entry, ok := k.cache[key]
	if !ok {
		// This should not happen
		logger.Error("Unknown role")
		return
	}
	delete(entry.Awaiting, cancel.result)
}

func (k *CredentialsPrefetcher) handleAdd(add addRequest) {
	logger := k.logger.With(logz.RoleArn(add.role.Arn), logz.RoleSessionName(add.role.SessionName))
	logger.Debug("Handling add request")
	key := keyForRole(add.role)
	if entry, ok := k.cache[key]; ok {
		// Role has an entry already
		if entry.TimesAddedCounter == 0 {
			// Entry is there but role hasn't been added before.
			// That means creds were requested before role was added.
			// Enqueue for refresh.
			k.enqueueForRefresh(&entry)
		}
		entry.TimesAddedCounter++ // increment the counter
		k.cache[key] = entry
		return
	}
	// Role does not have an entry
	entry := CacheEntry{
		Role:               add.role,
		TimesAddedCounter:  1,
		Awaiting:           make(map[chan<- credResponse]struct{}),
		EnqueuedForRefresh: true,
	}
	k.enqueueForRefresh(&entry)
	k.cache[key] = entry
	k.cacheSize.Set(float64(len(k.cache)))
}

func (k *CredentialsPrefetcher) handleRemove(remove removeRequest) {
	logger := k.logger.With(logz.RoleArn(remove.role.Arn), logz.RoleSessionName(remove.role.SessionName))
	logger.Debug("Removing role")
	key := keyForRole(remove.role)
	entry, ok := k.cache[key]
	if !ok {
		// Unknown role, this should not happen
		logger.Error("Unknown role")
		return
	}
	// Role is known, decrement the ref counter
	entry.TimesAddedCounter--
	if entry.TimesAddedCounter > 0 {
		// There are still references to this role out there
		k.cache[key] = entry
		logger.Debug("There are still references to the role, keeping in the cache")
		return
	}
	// No references, can drop from cache
	delete(k.cache, key)
	k.cacheSize.Set(float64(len(k.cache)))
	logger.Debug("Role removed from the cache")
	// Tell every awaiting client
	err := errors.New("role was removed")
	for c := range entry.Awaiting {
		c <- credResponse{
			err: err,
		}
	}
}

// CredentialsForRole fetches credentials from the cache.
// It blocks until credentials are available or the context signals done.
func (k *CredentialsPrefetcher) CredentialsForRole(ctx context.Context, role *iam4kube.IamRole) (*iam4kube.Credentials, error) {
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

func (k *CredentialsPrefetcher) Add(role *iam4kube.IamRole) {
	k.addCount.Inc()
	k.add <- addRequest{
		role: *role,
	}
}

func (k *CredentialsPrefetcher) Remove(role *iam4kube.IamRole) {
	k.removeCount.Inc()
	k.remove <- removeRequest{
		role: *role,
	}
}

// Inspect asynchronously executes f in the goroutine that owns the cache.
// f must not mutate cache to avoid interfering with internal invariants.
func (k *CredentialsPrefetcher) Inspect(f func(map[IamRoleKey]CacheEntry)) {
	k.inspect <- f
}

func (k *CredentialsPrefetcher) Metrics() Metrics {
	return Metrics{
		BusyWorkersNumber:  atomic.LoadInt32(&k.busyWorkersNumber),
		ToRefreshBufLength: atomic.LoadInt32(&k.toRefreshBufLength),
	}
}

// worker fetches credentials for roles it picks up from the channel.
// Results are pushed into the refreshed channel.
func (k *CredentialsPrefetcher) worker(ctx context.Context) {
	k.logger.Debug("Starting worker")
	defer k.logger.Debug("Stopping worker")
	for roleToRefresh := range k.toRefresh {
		if !k.workerRefreshRole(ctx, roleToRefresh) {
			break
		}
	}
}

func (k *CredentialsPrefetcher) workerRefreshRole(ctx context.Context, role iam4kube.IamRole) bool {
	atomic.AddInt32(&k.busyWorkersNumber, 1)
	defer atomic.AddInt32(&k.busyWorkersNumber, -1)
	l := k.logger.With(logz.RoleArn(role.Arn), logz.RoleSessionName(role.SessionName))
	for {
		k.refreshAttemptsTotal.Inc()
		l.Debug("Attempting to fetch credentials for role")
		if err := k.limiter.Wait(ctx); err != nil {
			if err != context.DeadlineExceeded && err != context.Canceled {
				l.Error("Unexpected error from rate limiter", zap.Error(err))
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
			l.Warn("Failed to fetch credentials for role", zap.Error(err))
			continue
		}
		k.getCredsSuccessCount.Inc()
		l.Debug("Successfully fetched credentials for role")
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

func (k *CredentialsPrefetcher) enqueueForRefresh(entry *CacheEntry) {
	k.toRefreshBuf.WriteOne(entry.Role)
	atomic.AddInt32(&k.toRefreshBufLength, 1)
	entry.EnqueuedForRefresh = true
}

func gaugeFuncForInt32(v *int32) func() float64 {
	return func() float64 {
		return float64(atomic.LoadInt32(v))
	}
}

func keyForRole(role iam4kube.IamRole) IamRoleKey {
	key := IamRoleKey{
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

type CacheEntry struct {
	Role               iam4kube.IamRole
	Creds              iam4kube.Credentials
	TimesAddedCounter  int // holds the number of times Add() was called for the corresponding role
	Awaiting           map[chan<- credResponse]struct{}
	HasCreds           bool // initially false, set to true when creds are retrieved for the first time
	EnqueuedForRefresh bool // true if creds are scheduled to be refreshed
}

type IamRoleKey struct {
	arn         arn.ARN
	sessionName string
	// Cannot use a pointer because pointers to equal strings may be not equal.
	externalID string
	// Set to true if externalID is not set.
	// This is to distinguish from the case when it is set to an empty string.
	idIsNotSet bool
}

func (k *IamRoleKey) String() string {
	return fmt.Sprintf("%s<sess=%s><extId=%s,%t>", k.arn, k.sessionName, k.externalID, k.idIsNotSet)
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
