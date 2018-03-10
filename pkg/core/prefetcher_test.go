package core

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ash2k/iam4kube"
	"github.com/ash2k/iam4kube/pkg/util/logz"
	"github.com/ash2k/stager/wait"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

const (
	accessKeyID     = "keyId"
	secretAccessKey = "secret"
	sessionToken    = "token"
)

func TestHappyPathWithPrefetchedCreds(t *testing.T) {
	t.Parallel()
	var wg wait.Group
	defer wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	kloud := &fakeKloud{}
	kloud.wg.Add(1)
	p := NewCredentialsPrefetcher(logz.DevelopmentLogger(), kloud, rate.NewLimiter(2, 2))

	wg.StartWithContext(ctx, p.Run)

	r := role()
	p.Add(r)

	kloud.wg.Wait() // wait until creds have been fetched

	creds, err := p.CredentialsForRole(context.Background(), r)
	require.NoError(t, err)
	assert.Equal(t, accessKeyID, creds.AccessKeyID)
	assert.Equal(t, secretAccessKey, creds.SecretAccessKey)
	assert.Equal(t, sessionToken, creds.SessionToken)
}

func TestHappyPathWithCredsBeingPrefetched(t *testing.T) {
	t.Parallel()
	var wg wait.Group
	defer wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	kloud := &fakeSlowKloud{}
	p := NewCredentialsPrefetcher(logz.DevelopmentLogger(), kloud, rate.NewLimiter(2, 2))

	wg.StartWithContext(ctx, p.Run)

	r := role()
	p.Add(r)

	creds, err := p.CredentialsForRole(context.Background(), r)
	require.NoError(t, err)
	assert.Equal(t, accessKeyID, creds.AccessKeyID)
	assert.Equal(t, secretAccessKey, creds.SecretAccessKey)
	assert.Equal(t, sessionToken, creds.SessionToken)
}

func TestUnblocksAwaitingCallersOnStop(t *testing.T) {
	t.Parallel()
	var wg wait.Group
	defer wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	kloud := &fakeSlowFailingKloud{}
	p := NewCredentialsPrefetcher(logz.DevelopmentLogger(), kloud, rate.NewLimiter(2, 2))

	wg.StartWithContext(ctx, p.Run)

	r := role()
	p.Add(r)
	_, err := p.CredentialsForRole(context.Background(), r)
	assert.Equal(t, context.DeadlineExceeded, errors.Cause(err))
}

func TestImpatientCaller(t *testing.T) {
	t.Parallel()
	var wg wait.Group
	defer wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	kloud := &fakeSlowKloud{}
	p := NewCredentialsPrefetcher(logz.DevelopmentLogger(), kloud, rate.NewLimiter(2, 2))

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
	p := NewCredentialsPrefetcher(logz.DevelopmentLogger(), kloud, rate.NewLimiter(2, 2))

	wg.StartWithContext(ctx, p.Run)

	r := role()
	p.Add(r)

	ctxReq, cancelReq := context.WithCancel(context.Background())
	cancelReq() // cancel it before the request

	_, err := p.CredentialsForRole(ctxReq, r)
	assert.Equal(t, context.Canceled, errors.Cause(err))
}

type fakeKloud struct {
	wg sync.WaitGroup
}

func (k *fakeKloud) CredentialsForRole(ctx context.Context, role *iam4kube.IamRole) (*iam4kube.Credentials, error) {
	defer k.wg.Done()
	return &iam4kube.Credentials{
		LastUpdated:     time.Now(),
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
		Expiration:      time.Now().Add(10 * time.Minute),
	}, nil
}

type fakeSlowKloud struct {
}

func (k *fakeSlowKloud) CredentialsForRole(ctx context.Context, role *iam4kube.IamRole) (*iam4kube.Credentials, error) {
	err := sleep(ctx, 100*time.Millisecond)
	if err != nil {
		return nil, err
	}
	return &iam4kube.Credentials{
		LastUpdated:     time.Now(),
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
		Expiration:      time.Now().Add(10 * time.Minute),
	}, nil
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
		Arn: a,
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
