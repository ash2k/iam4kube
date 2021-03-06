package core

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ash2k/iam4kube"
	"github.com/ash2k/stager/wait"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"golang.org/x/time/rate"
)

const (
	accessKeyID     = "keyId"
	secretAccessKey = "secret"
	sessionToken    = "token"
)

var (
	_ Kloud = (*CredentialsPrefetcher)(nil)
)

func TestHappyPathWithPrefetchedCreds(t *testing.T) {
	t.Parallel()
	var wg wait.Group
	defer wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	kloud := &fakeKloud{}
	kloud.fetchedWg.Add(1)
	p := newPrefetcher(t, kloud)

	wg.StartWithContext(ctx, p.Run)

	r := role()
	p.Add(r)

	kloud.fetchedWg.Wait() // wait until creds have been fetched

	assertCreds(t, p, r)
}

func TestHappyPathWithCredsBeingPrefetched(t *testing.T) {
	t.Parallel()
	var wg wait.Group
	defer wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	kloud := &fakeSlowKloud{}
	p := newPrefetcher(t, kloud)

	wg.StartWithContext(ctx, p.Run)

	r := role()
	p.Add(r)

	assertCreds(t, p, r)
}

func TestHappyPathRoleAddedLater(t *testing.T) {
	t.Parallel()
	t.Run("single request", func(t *testing.T) {
		t.Parallel()
		var wg wait.Group
		defer wg.Wait()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		kloud := &fakeKloud{}
		kloud.fetchedWg.Add(1)
		p := newPrefetcher(t, kloud)

		wg.StartWithContext(ctx, p.Run)

		r := role()
		go func() {
			time.Sleep(20 * time.Millisecond)
			p.Add(r)
		}()

		assertCreds(t, p, r)
	})
	t.Run("two concurrent requests", func(t *testing.T) {
		t.Parallel()
		var wg wait.Group
		defer wg.Wait()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		kloud := &fakeKloud{}
		kloud.fetchedWg.Add(1)
		p := newPrefetcher(t, kloud)

		wg.StartWithContext(ctx, p.Run)

		r := role()
		go func() {
			time.Sleep(20 * time.Millisecond)
			p.Add(r)
		}()

		wg.Start(func() {
			// Another concurrent request
			assertCreds(t, p, r)
		})

		assertCreds(t, p, r)
	})
	t.Run("added multiple times then removed", func(t *testing.T) {
		t.Parallel()
		var wg wait.Group
		defer wg.Wait()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		kloud := &fakeKloud{}
		kloud.fetchedWg.Add(1)
		p := newPrefetcher(t, kloud)

		wg.StartWithContext(ctx, p.Run)

		r := role()
		p.Add(r)
		p.Add(r)
		p.Remove(r)

		assertCreds(t, p, r)
		p.Remove(r)

		ctxReq, cancelReq := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancelReq()

		_, err := p.CredentialsForRole(ctxReq, r)
		assert.Equal(t, context.DeadlineExceeded, errors.Cause(err))

	})
}

func TestCredsForUnknownRole(t *testing.T) {
	t.Parallel()
	t.Run("single timing out request", func(t *testing.T) {
		t.Parallel()
		var wg wait.Group
		defer wg.Wait()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		kloud := &fakeNeverInvokedKloud{t: t}
		p := newPrefetcher(t, kloud)

		wg.StartWithContext(ctx, p.Run)

		ctxReq, cancelReq := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancelReq()
		r := role()

		_, err := p.CredentialsForRole(ctxReq, r)
		assert.Equal(t, context.DeadlineExceeded, errors.Cause(err))

		workingKloud := &fakeKloud{}
		workingKloud.fetchedWg.Add(1)
		kloud.setDelegate(workingKloud)

		p.Add(r)

		assertCreds(t, p, r)
	})
	t.Run("two sequential timing out requests", func(t *testing.T) {
		t.Parallel()
		var wg wait.Group
		defer wg.Wait()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		kloud := &fakeNeverInvokedKloud{t: t}
		p := newPrefetcher(t, kloud)

		wg.StartWithContext(ctx, p.Run)

		ctxReq1, cancelReq1 := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancelReq1()
		r := role()

		_, err := p.CredentialsForRole(ctxReq1, r)
		assert.Equal(t, context.DeadlineExceeded, errors.Cause(err))

		ctxReq2, cancelReq2 := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancelReq2()
		_, err = p.CredentialsForRole(ctxReq2, r)
		assert.Equal(t, context.DeadlineExceeded, errors.Cause(err))

		workingKloud := &fakeKloud{}
		workingKloud.fetchedWg.Add(1)
		kloud.setDelegate(workingKloud)
		p.Add(r)

		assertCreds(t, p, r)
	})
	t.Run("role added and removed after creds fetched", func(t *testing.T) {
		t.Parallel()
		var wg wait.Group
		defer wg.Wait()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		kloud := &fakeKloud{}
		kloud.fetchedWg.Add(1)
		p := newPrefetcher(t, kloud)

		wg.StartWithContext(ctx, p.Run)

		r := role()
		p.Add(r)
		kloud.fetchedWg.Wait() // Wait until the creds have been fetched
		p.Remove(r)

		ctxReq, cancelReq := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancelReq()
		_, err := p.CredentialsForRole(ctxReq, r)
		assert.Equal(t, context.DeadlineExceeded, errors.Cause(err))
	})
	t.Run("role added and removed before creds fetched", func(t *testing.T) {
		t.Parallel()
		var wg wait.Group
		defer wg.Wait()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		kloud := &fakeSlowKloud{}
		p := newPrefetcher(t, kloud)

		wg.StartWithContext(ctx, p.Run)

		r := role()
		p.Add(r)
		p.Remove(r)

		ctxReq, cancelReq := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancelReq()
		_, err := p.CredentialsForRole(ctxReq, r)
		assert.Equal(t, context.DeadlineExceeded, errors.Cause(err))
	})
	t.Run("role added and removed while creds are being fetched", func(t *testing.T) {
		t.Parallel()
		var wg wait.Group
		defer wg.Wait()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		kloud := &fakeSlowKloud{}
		p := newPrefetcher(t, kloud)

		wg.StartWithContext(ctx, p.Run)

		r := role()
		p.Add(r)
		go func() {
			time.Sleep(10 * time.Millisecond)
			p.Remove(r)
		}()

		_, err := p.CredentialsForRole(context.Background(), r)
		assert.EqualError(t, err, "role was removed")
	})
}

func TestUnblocksAwaitingCallersOnStop(t *testing.T) {
	t.Parallel()
	t.Run("awaiting with slow kloud", func(t *testing.T) {
		t.Parallel()
		var wg wait.Group
		defer wg.Wait()
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		kloud := &fakeSlowFailingKloud{}
		p := newPrefetcher(t, kloud)

		wg.StartWithContext(ctx, p.Run)

		r := role()
		p.Add(r)
		_, err := p.CredentialsForRole(context.Background(), r)
		assert.Equal(t, context.DeadlineExceeded, errors.Cause(err))
	})
	t.Run("awaiting unknown role", func(t *testing.T) {
		t.Parallel()
		var wg wait.Group
		defer wg.Wait()
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		kloud := &fakeNeverInvokedKloud{t: t}
		p := newPrefetcher(t, kloud)

		wg.StartWithContext(ctx, p.Run)

		r := role()
		_, err := p.CredentialsForRole(context.Background(), r)
		assert.Equal(t, context.DeadlineExceeded, errors.Cause(err))
	})
}

func TestImpatientCaller(t *testing.T) {
	t.Parallel()
	var wg wait.Group
	defer wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	kloud := &fakeSlowKloud{}
	p := newPrefetcher(t, kloud)

	wg.StartWithContext(ctx, p.Run)

	r := role()
	p.Add(r)

	ctxReq, cancelReq := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancelReq()

	_, err := p.CredentialsForRole(ctxReq, r)
	assert.Equal(t, context.DeadlineExceeded, errors.Cause(err))
}

func TestCallerWithCancelledContext(t *testing.T) {
	t.Parallel()
	var wg wait.Group
	defer wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	kloud := &fakeSlowKloud{}
	p := newPrefetcher(t, kloud)

	wg.StartWithContext(ctx, p.Run)

	r := role()
	p.Add(r)

	ctxReq, cancelReq := context.WithCancel(context.Background())
	cancelReq() // cancel it before the request

	_, err := p.CredentialsForRole(ctxReq, r)
	assert.Equal(t, context.Canceled, errors.Cause(err))
}

func TestRefresh(t *testing.T) {
	t.Parallel()
	var wg wait.Group
	defer wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	kloud := &fakeKloud{
		expireIn: 1 * time.Minute,
	}
	kloud.fetchedWg.Add(2)
	p := newPrefetcher(t, kloud)
	p.freshnessCheckPeriod = time.Second

	wg.StartWithContext(ctx, p.Run)

	r := role()
	p.Add(r)
	kloud.fetchedWg.Wait()
}

func TestRefreshShouldNotUnblock(t *testing.T) {
	t.Parallel()
	var wg wait.Group
	defer wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	kloud := &fakeNeverInvokedKloud{t: t}
	p := newPrefetcher(t, kloud)
	p.freshnessCheckPeriod = time.Second

	wg.StartWithContext(ctx, p.Run)

	ctxReq, cancelReq := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelReq()
	r := role()
	_, err := p.CredentialsForRole(ctxReq, r)
	assert.Equal(t, context.DeadlineExceeded, errors.Cause(err))
}

func TestGetTriggersRefresh(t *testing.T) {
	t.Parallel()
	var wg wait.Group
	defer wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	kloud := &fakeKloud{
		expireIn: freshnessThresholdForGet / 2,
	}
	kloud.fetchedWg.Add(1)
	p := newPrefetcher(t, kloud)

	wg.StartWithContext(ctx, p.Run)

	r := role()
	p.Add(r)
	kloud.fetchedWg.Wait()
	time.Sleep(time.Second) // wait until fetched creds are stored in the cache
	kloud.fetchedWg.Add(1)
	assertCreds(t, p, r)
}

func assertCreds(t *testing.T, prefetcher *CredentialsPrefetcher, role *iam4kube.IamRole) {
	creds, err := prefetcher.CredentialsForRole(context.Background(), role)
	require.NoError(t, err)
	assert.Equal(t, accessKeyID, creds.AccessKeyID)
	assert.Equal(t, secretAccessKey, creds.SecretAccessKey)
	assert.Equal(t, sessionToken, creds.SessionToken)
}

func newPrefetcher(t *testing.T, kloud Kloud) *CredentialsPrefetcher {
	pref, err := NewCredentialsPrefetcher(zaptest.NewLogger(t), kloud, prometheus.NewPedanticRegistry(),
		rate.NewLimiter(2, 2), 2)
	require.NoError(t, err)
	return pref
}

type fakeKloud struct {
	fetchedWg sync.WaitGroup
	expireIn  time.Duration
}

func (k *fakeKloud) CredentialsForRole(ctx context.Context, role *iam4kube.IamRole) (*iam4kube.Credentials, error) {
	defer k.fetchedWg.Done()
	now := time.Now().UTC()
	expireIn := k.expireIn
	if expireIn == 0 {
		expireIn = 10*time.Minute + freshnessThresholdForPeriodicCheck
	}
	return &iam4kube.Credentials{
		LastUpdated:     now,
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
		Expiration:      now.Add(expireIn),
	}, nil
}

type fakeSlowKloud struct {
}

func (k *fakeSlowKloud) CredentialsForRole(ctx context.Context, role *iam4kube.IamRole) (*iam4kube.Credentials, error) {
	err := sleep(ctx, 100*time.Millisecond)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	return &iam4kube.Credentials{
		LastUpdated:     now,
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
		Expiration:      now.Add(10*time.Minute + freshnessThresholdForPeriodicCheck),
	}, nil
}

type fakeNeverInvokedKloud struct {
	t     *testing.T
	mx    sync.Mutex
	kloud Kloud
}

func (k *fakeNeverInvokedKloud) setDelegate(kloud Kloud) {
	k.mx.Lock()
	defer k.mx.Unlock()
	k.kloud = kloud
}

func (k *fakeNeverInvokedKloud) delegate() Kloud {
	k.mx.Lock()
	defer k.mx.Unlock()
	return k.kloud
}

func (k *fakeNeverInvokedKloud) CredentialsForRole(ctx context.Context, role *iam4kube.IamRole) (*iam4kube.Credentials, error) {
	delegate := k.delegate()
	if delegate == nil {
		k.t.Errorf("should not have been called for role %s", role)
		return &iam4kube.Credentials{}, nil
	}
	return delegate.CredentialsForRole(ctx, role)
}

type fakeSlowFailingKloud struct {
}

func (k *fakeSlowFailingKloud) CredentialsForRole(ctx context.Context, role *iam4kube.IamRole) (*iam4kube.Credentials, error) {
	err := sleep(ctx, 100*time.Millisecond)
	if err != nil {
		return nil, err
	}
	return nil, errors.New("bla")
}

func role() *iam4kube.IamRole {
	a, err := arn.Parse("arn:aws:iam::123456789012:role/this/is/a/path/roleName")
	if err != nil {
		panic(err)
	}
	return &iam4kube.IamRole{
		Arn:         a,
		SessionName: "default/serviceaccounts/accountname",
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	select {
	case <-ctx.Done():
		timer.Stop()
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
