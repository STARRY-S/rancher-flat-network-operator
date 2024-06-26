package service

import (
	"fmt"
	"strings"
	"time"

	flv1 "github.com/cnrancher/rancher-flat-network-operator/pkg/apis/flatnetwork.pandaria.io/v1"
	"github.com/cnrancher/rancher-flat-network-operator/pkg/utils"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func (h *handler) handleFlatNetworkService(
	svc *corev1.Service,
) (*corev1.Service, error) {
	logrus.WithFields(fieldsService(svc)).
		Debugf("service is a flat-network service")

	pods, err := h.podCache.List(svc.Namespace, labels.SelectorFromSet(svc.Spec.Selector))
	if err != nil {
		return svc, fmt.Errorf("failed to list pod by selector [%v] on service [%v/%v]: %w",
			svc.Spec.Selector, svc.Namespace, svc.Name, err)
	}
	ok, err := h.shouldDeleteFlatNetworkService(svc, pods)
	if err != nil {
		logrus.WithFields(fieldsService(svc)).
			Errorf("failed to sync flat-network service: %v", err)
		return nil, err
	}
	if ok {
		logrus.WithFields(fieldsService(svc)).
			Infof("request to delete flat-network service")
		err = h.serviceClient.Delete(svc.Namespace, svc.Name, &metav1.DeleteOptions{})
		if err != nil {
			logrus.WithFields(fieldsService(svc)).
				Errorf("failed to delete flat-network service: %v", err)
			return svc, err
		}
		return svc, nil
	}

	if err = h.syncServiceEndpoints(svc, pods); err != nil {
		return svc, err
	}
	// Requeue flat-network service every 10 seconds.
	h.serviceEnqueueAfter(svc.Namespace, svc.Name, time.Second*10)
	return svc, nil
}

func (h *handler) shouldDeleteFlatNetworkService(
	svc *corev1.Service, pods []*corev1.Pod,
) (bool, error) {
	if len(svc.Spec.Selector) == 0 {
		return true, nil
	}

	originalServiceName := strings.TrimSuffix(svc.Name, flatNetworkServiceNameSuffix)
	originalService, err := h.serviceCache.Get(svc.Namespace, originalServiceName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Delete if no original service.
			logrus.WithFields(fieldsService(svc)).
				Infof("original service of flat-network service [%v/%v] not found",
					svc.Namespace, originalServiceName)
			return true, nil
		}
		return false, fmt.Errorf("failed to get service [%v/%v] from cache: %w",
			svc.Namespace, originalService.Name, err)
	}

	if len(pods) == 0 {
		logrus.WithFields(fieldsService(svc)).
			Infof("no pods on flat-network service [%v/%v]",
				svc.Namespace, svc.Name)
		return true, nil
	}

	// Workload of this svc disabled flat-network service by annotation.
	for _, pod := range pods {
		if pod == nil {
			continue
		}
		annotations := pod.Annotations
		if annotations != nil && annotations[flv1.AnnotationFlatNetworkService] == "disabled" {
			logrus.WithFields(fieldsService(svc)).
				Infof("annotation [%v: disabled] found, flat-network service disabled",
					flv1.AnnotationFlatNetworkService)
			return true, nil
		}
	}

	// Workload does not enabled flat-network.
	var podUseFlatNetwork bool
	for _, pod := range pods {
		if pod == nil {
			continue
		}
		if utils.IsPodEnabledFlatNetwork(pod) {
			podUseFlatNetwork = true
			break
		}
	}
	if !podUseFlatNetwork {
		logrus.WithFields(fieldsService(svc)).
			Infof("workload does not use flat-network")
	}

	return !podUseFlatNetwork, nil
}
