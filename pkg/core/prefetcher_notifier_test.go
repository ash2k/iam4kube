package core

import (
	"testing"

	"github.com/ash2k/iam4kube"
	i4k_testing "github.com/ash2k/iam4kube/pkg/util/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	svcAccName        = "svcAccName"
	namespace         = "svcAccNamespace"
	roleArn           = "arn:aws:iam::123456789012:role/this/is/a/path/roleName"
	roleOldArn        = "arn:aws:iam::123456789012:role/old-role-name"
	roleOldExternalId = "blablabla"
)

func TestOnAddShouldNotAddNoRole(t *testing.T) {
	t.Parallel()
	pref, notif := initObjs(t)
	notif.OnAdd(svcAccNoRole())
	assert.Empty(t, pref.add)
}

func TestOnAddShouldNotAddInvalidRole(t *testing.T) {
	t.Parallel()
	pref, notif := initObjs(t)
	notif.OnAdd(svcAccInvalidRole())
	assert.Empty(t, pref.add)
}

func TestOnAddShouldAdd(t *testing.T) {
	t.Parallel()
	pref, notif := initObjs(t)
	notif.OnAdd(svcAccWithRole())
	require.Len(t, pref.add, 1)
	assertRole(t, pref.add[0])
}

func TestOnUpdateRoleAdded(t *testing.T) {
	t.Parallel()
	pref, notif := initObjs(t)
	notif.OnUpdate(svcAccNoRole(), svcAccWithRole())
	assert.Len(t, pref.add, 1)
	assert.Empty(t, pref.remove)
}

func TestOnUpdateRoleRemoved(t *testing.T) {
	t.Parallel()
	pref, notif := initObjs(t)
	notif.OnUpdate(svcAccWithRole(), svcAccNoRole())
	assert.Empty(t, pref.add)
	require.Len(t, pref.remove, 1)
	assertRole(t, pref.remove[0])
}

func TestOnUpdateRoleUpdated(t *testing.T) {
	t.Parallel()
	pref, notif := initObjs(t)
	notif.OnUpdate(svcAccWithOldRole(), svcAccWithRole())
	require.Len(t, pref.add, 1)
	assertRole(t, pref.add[0])
	require.Len(t, pref.remove, 1)
	assertOldRole(t, pref.remove[0])
}

func TestOnUpdateSameRole(t *testing.T) {
	t.Parallel()
	pref, notif := initObjs(t)
	notif.OnUpdate(svcAccWithRole(), svcAccWithRole())
	assert.Empty(t, pref.add)
	assert.Empty(t, pref.remove)
}

func TestOnUpdateNoRoles(t *testing.T) {
	t.Parallel()
	pref, notif := initObjs(t)
	notif.OnUpdate(svcAccNoRole(), svcAccNoRole())
	assert.Empty(t, pref.add)
	assert.Empty(t, pref.remove)
}

func TestOnUpdateInvalidToValid(t *testing.T) {
	t.Parallel()
	pref, notif := initObjs(t)
	notif.OnUpdate(svcAccInvalidRole(), svcAccWithRole())
	require.Len(t, pref.add, 1)
	assertRole(t, pref.add[0])
	assert.Empty(t, pref.remove)
}

func TestOnUpdateValidToInvalid(t *testing.T) {
	t.Parallel()
	pref, notif := initObjs(t)
	notif.OnUpdate(svcAccWithRole(), svcAccInvalidRole())
	assert.Empty(t, pref.add)
	require.Len(t, pref.remove, 1)
	assertRole(t, pref.remove[0])
}

func TestOnUpdateInvalidToInvalid(t *testing.T) {
	t.Parallel()
	pref, notif := initObjs(t)
	notif.OnUpdate(svcAccInvalidRole(), svcAccInvalidRole())
	assert.Empty(t, pref.add)
	assert.Empty(t, pref.remove)
}

func TestOnDeleteShouldNotRemoveNoRole(t *testing.T) {
	t.Parallel()
	pref, notif := initObjs(t)
	notif.OnDelete(svcAccNoRole())
	assert.Empty(t, pref.remove)
}

func TestOnDeleteShouldNotRemoveInvalidRole(t *testing.T) {
	t.Parallel()
	pref, notif := initObjs(t)
	notif.OnDelete(svcAccInvalidRole())
	assert.Empty(t, pref.remove)
}

func TestOnDeleteShouldRemove(t *testing.T) {
	t.Parallel()
	pref, notif := initObjs(t)
	notif.OnDelete(svcAccWithRole())
	require.Len(t, pref.remove, 1)
	assertRole(t, pref.remove[0])
}

// this method smells like overspecification but we need to ensure the correct role is added/removed (old vs new).
func assertRole(t *testing.T, role *iam4kube.IamRole) {
	assert.Equal(t, roleArn, role.Arn.String())
	assert.Equal(t, namespace+"@"+svcAccName, role.SessionName)
	assert.Nil(t, role.ExternalID)
}

func assertOldRole(t *testing.T, role *iam4kube.IamRole) {
	assert.Equal(t, roleOldArn, role.Arn.String())
	assert.Equal(t, namespace+"@"+svcAccName, role.SessionName)
	assert.Equal(t, roleOldExternalId, *role.ExternalID)
}

func svcAccNoRole() *core_v1.ServiceAccount {
	return &core_v1.ServiceAccount{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      svcAccName,
			Namespace: namespace,
		},
	}
}

func svcAccInvalidRole() *core_v1.ServiceAccount {
	return &core_v1.ServiceAccount{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      svcAccName,
			Namespace: namespace,
			Annotations: map[string]string{
				iam4kube.IamRoleArnAnnotation: "role-invalid",
			},
		},
	}
}

func svcAccWithRole() *core_v1.ServiceAccount {
	return &core_v1.ServiceAccount{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      svcAccName,
			Namespace: namespace,
			Annotations: map[string]string{
				iam4kube.IamRoleArnAnnotation: roleArn,
			},
		},
	}
}

func svcAccWithOldRole() *core_v1.ServiceAccount {
	return &core_v1.ServiceAccount{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      svcAccName,
			Namespace: namespace,
			Annotations: map[string]string{
				iam4kube.IamRoleArnAnnotation:        roleOldArn,
				iam4kube.IamRoleExternalIdAnnotation: roleOldExternalId,
			},
		},
	}
}

func initObjs(t *testing.T) (*recordingPrefetcher, *PrefetcherNotifier) {
	pref := &recordingPrefetcher{}
	notif := &PrefetcherNotifier{
		Logger:     i4k_testing.DevelopmentLogger(t),
		Prefetcher: pref,
	}
	return pref, notif
}

type recordingPrefetcher struct {
	add    []*iam4kube.IamRole
	remove []*iam4kube.IamRole
}

func (p *recordingPrefetcher) Add(role *iam4kube.IamRole) {
	p.add = append(p.add, role)
}

func (p *recordingPrefetcher) Remove(role *iam4kube.IamRole) {
	p.remove = append(p.remove, role)
}
