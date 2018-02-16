package kube

import (
	"context"

	"github.com/ash2k/iam4kube"

	"github.com/pkg/errors"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

const (
	podByIpIndex = "podByIpIndex"
)

type Kroler struct {
	podIdx    cache.Indexer
	svcAccIdx cache.Indexer
}

func NewKroler(podsInf, svcAccInf cache.SharedIndexInformer) (*Kroler, error) {
	err := podsInf.AddIndexers(cache.Indexers{
		podByIpIndex: podByIpIndexFunc,
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &Kroler{
		podIdx:    podsInf.GetIndexer(),
		svcAccIdx: svcAccInf.GetIndexer(),
	}, nil
}

func (k *Kroler) RoleForIp(ctx context.Context, ip iam4kube.IP) (*iam4kube.IamRole, error) {
	// TODO
	return nil, nil
}

func podByIpIndexFunc(obj interface{}) ([]string, error) {
	pod := obj.(core_v1.Pod)
	ip := pod.Status.PodIP
	if ip == "" {
		return nil, nil
	}
	return []string{ip}, nil
}
