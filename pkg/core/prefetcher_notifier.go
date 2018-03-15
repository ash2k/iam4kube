package core

import (
	"github.com/ash2k/iam4kube/pkg/kube"
	"go.uber.org/zap"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

func NotifyPrefetcher(logger *zap.Logger, prefetcher *CredentialsPrefetcher, svcAccInf cache.SharedIndexInformer) {
	svcAccInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			svcAcc := obj.(*core_v1.ServiceAccount)
			role, err := kube.IamRoleFromServiceAccount(svcAcc)
			if err != nil {
				logger.With(zap.Error(err)).Sugar().Errorf(
					"Failed to get IAM role from ServiceAccount %q in namespace %q",
					svcAcc.Name, svcAcc.Namespace)
				return
			}
			if role == nil {
				logger.Sugar().Debugf("No IAM role found on ServiceAccount %q in namespace %q",
					svcAcc.Name, svcAcc.Namespace)
				return
			}
			prefetcher.Add(role)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			svcAccOld := oldObj.(*core_v1.ServiceAccount)
			svcAccNew := newObj.(*core_v1.ServiceAccount)
			roleOld, errOld := kube.IamRoleFromServiceAccount(svcAccOld)
			roleNew, errNew := kube.IamRoleFromServiceAccount(svcAccNew)

			if errOld == nil && errNew == nil {
				if roleOld == nil && roleNew != nil {
					// Role added
					prefetcher.Add(roleNew)
				} else if roleOld != nil && roleNew == nil {
					// Role removed
					prefetcher.Remove(roleOld)
				} else if roleOld != nil && roleNew != nil && !roleOld.Equals(roleNew) {
					// Role modified
					prefetcher.Remove(roleOld)
					prefetcher.Add(roleNew)
				}
				// Otherwise no role defined or not modified
			} else if errOld != nil && errNew == nil {
				// Was invalid, now valid. Add
				prefetcher.Add(roleNew)
			} else if errOld == nil && errNew != nil {
				// Was valid, now invalid. Remove
				prefetcher.Remove(roleOld)
			} else {
				// Was invalid and is still invalid. Log new error
				logger.With(zap.Error(errNew)).Sugar().Errorf(
					"Failed to get IAM role from ServiceAccount %q in namespace %q",
					svcAccNew.Name, svcAccNew.Namespace)
			}
		},
		DeleteFunc: func(obj interface{}) {
			svcAcc, ok := obj.(*core_v1.ServiceAccount)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					logger.Sugar().Errorf("Delete event with unrecognized object type: %T", obj)
					return
				}
				svcAcc, ok = tombstone.Obj.(*core_v1.ServiceAccount)
				if !ok {
					logger.Sugar().Errorf("Delete tombstone with unrecognized object type: %T", tombstone.Obj)
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
			prefetcher.Remove(role)
		},
	})
}
