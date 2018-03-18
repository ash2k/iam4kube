package core

import (
	"github.com/ash2k/iam4kube/pkg/kube"
	"go.uber.org/zap"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

type PrefetcherNotifier struct {
	Logger     *zap.Logger
	Prefetcher *CredentialsPrefetcher
}

func (p *PrefetcherNotifier) OnAdd(obj interface{}) {
	svcAcc := obj.(*core_v1.ServiceAccount)
	role, err := kube.IamRoleFromServiceAccount(svcAcc)
	if err != nil {
		p.Logger.With(zap.Error(err)).Sugar().Errorf(
			"Failed to get IAM role from ServiceAccount %q in namespace %q",
			svcAcc.Name, svcAcc.Namespace)
		return
	}
	if role == nil {
		p.Logger.Sugar().Debugf("No IAM role found on ServiceAccount %q in namespace %q",
			svcAcc.Name, svcAcc.Namespace)
		return
	}
	p.Prefetcher.Add(role)
}

func (p *PrefetcherNotifier) OnUpdate(oldObj, newObj interface{}) {
	svcAccOld := oldObj.(*core_v1.ServiceAccount)
	svcAccNew := newObj.(*core_v1.ServiceAccount)
	roleOld, errOld := kube.IamRoleFromServiceAccount(svcAccOld)
	roleNew, errNew := kube.IamRoleFromServiceAccount(svcAccNew)

	if errOld == nil && errNew == nil {
		if roleOld == nil && roleNew != nil {
			// Role added
			p.Prefetcher.Add(roleNew)
		} else if roleOld != nil && roleNew == nil {
			// Role removed
			p.Prefetcher.Remove(roleOld)
		} else if roleOld != nil && roleNew != nil && !roleOld.Equals(roleNew) {
			// Role modified
			p.Prefetcher.Remove(roleOld)
			p.Prefetcher.Add(roleNew)
		}
		// Otherwise no role defined or not modified
	} else if errOld != nil && errNew == nil {
		// Was invalid, now valid. Add
		p.Prefetcher.Add(roleNew)
	} else if errOld == nil && errNew != nil {
		// Was valid, now invalid. Remove
		p.Prefetcher.Remove(roleOld)
	} else {
		// Was invalid and is still invalid. Log new error
		p.Logger.With(zap.Error(errNew)).Sugar().Errorf(
			"Failed to get IAM role from ServiceAccount %q in namespace %q",
			svcAccNew.Name, svcAccNew.Namespace)
	}
}

func (p *PrefetcherNotifier) OnDelete(obj interface{}) {
	svcAcc, ok := obj.(*core_v1.ServiceAccount)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			p.Logger.Sugar().Errorf("Delete event with unrecognized object type: %T", obj)
			return
		}
		svcAcc, ok = tombstone.Obj.(*core_v1.ServiceAccount)
		if !ok {
			p.Logger.Sugar().Errorf("Delete tombstone with unrecognized object type: %T", tombstone.Obj)
			return
		}
	}
	role, err := kube.IamRoleFromServiceAccount(svcAcc)
	if err != nil {
		// We have logged this error when the object was added
		return
	}
	if role == nil {
		return
	}
	p.Prefetcher.Remove(role)
}
