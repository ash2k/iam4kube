package ip2service

import (
	"go.uber.org/zap"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

type RouterIface interface {
	EnsureRoute(targetPort int32, ips []string) error
}

type EndpointsEventHandler struct {
	Logger            *zap.Logger
	ServiceName       string
	ServiceTargetPort int32
	Router            RouterIface
}

func (h *EndpointsEventHandler) OnAdd(obj interface{}) {
	h.handle(obj.(*core_v1.Endpoints))
}

func (h *EndpointsEventHandler) OnUpdate(oldObj, newObj interface{}) {
	h.handle(newObj.(*core_v1.Endpoints))
}

func (h *EndpointsEventHandler) OnDelete(obj interface{}) {
	endpoints, ok := obj.(*core_v1.Endpoints)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			h.Logger.Sugar().Errorf("Delete event with unrecognized object type: %T", obj)
			return
		}
		endpoints, ok = tombstone.Obj.(*core_v1.Endpoints)
		if !ok {
			h.Logger.Sugar().Errorf("Delete tombstone with unrecognized object type: %T", tombstone.Obj)
			return
		}
	}
	h.handle(endpoints)
}

func (h *EndpointsEventHandler) handle(obj *core_v1.Endpoints) {
	if obj.Name != h.ServiceName {
		// Event for some other Service/Endpoints
		return
	}
	ipsMap := make(map[string]struct{})

	// Extract all ready ips with a specific port open
	for _, subset := range obj.Subsets {
		for _, port := range subset.Ports {
			if port.Port == h.ServiceTargetPort {
				for _, address := range subset.Addresses {
					// TODO address.IP can be a host name in the future - see field comment
					ipsMap[address.IP] = struct{}{}
				}
			}
		}
	}

	ips := make([]string, 0, len(ipsMap))
	for ip := range ipsMap {
		ips = append(ips, ip)
	}
	if err := h.Router.EnsureRoute(h.ServiceTargetPort, ips); err != nil {
		h.Logger.Error("Failed to ensure route is configured", zap.Error(err))
		return
	}
	h.Logger.Sugar().Infof("Ensured route is configured with ips %s", ips)
}
