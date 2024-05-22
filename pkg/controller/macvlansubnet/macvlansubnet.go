package macvlansubnet

import (
	"context"
	"fmt"
	"time"

	"github.com/cnrancher/flat-network-operator/pkg/ipcalc"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/util/retry"

	macvlanv1 "github.com/cnrancher/flat-network-operator/pkg/apis/macvlan.cluster.cattle.io/v1"
	corecontroller "github.com/cnrancher/flat-network-operator/pkg/generated/controllers/core/v1"
	macvlancontroller "github.com/cnrancher/flat-network-operator/pkg/generated/controllers/macvlan.cluster.cattle.io/v1"
)

const (
	controllerName       = "macvlansubnet"
	controllerRemoveName = "macvlansubnet-remove"
)

const (
	macvlanSubnetPendingPhase = ""
	macvlanSubnetActivePhase  = "Active"
	macvlanSubnetFailedPhase  = "Failed"

	subnetMacvlanIPCountAnnotation = "macvlanipCount"
	subnetGatewayCacheValue        = "subnet gateway ip"
)

type handler struct {
	macvlanSubnets macvlancontroller.MacvlanSubnetClient
	pods           corecontroller.PodCache

	macvlansubnetEnqueueAfter func(string, string, time.Duration)
	macvlansubnetEnqueue      func(string, string)
}

func Register(
	ctx context.Context,
	macvlanSubnets macvlancontroller.MacvlanSubnetController,
	pods corecontroller.PodCache,
) {
	h := &handler{
		macvlanSubnets: macvlanSubnets,
		pods:           pods,

		macvlansubnetEnqueueAfter: macvlanSubnets.EnqueueAfter,
		macvlansubnetEnqueue:      macvlanSubnets.Enqueue,
	}

	logrus.Infof("Setting up MacvlanSubnet event handler")
	macvlanSubnets.OnChange(ctx, controllerName, h.handleMacvlanSubnetError(h.onMacvlanSubnetChanged))
	macvlanSubnets.OnRemove(ctx, controllerName, h.onMacvlanSubnetRemoved)
}

func (h *handler) handleMacvlanSubnetError(
	onChange func(string, *macvlanv1.MacvlanSubnet) (*macvlanv1.MacvlanSubnet, error),
) func(string, *macvlanv1.MacvlanSubnet) (*macvlanv1.MacvlanSubnet, error) {
	return func(key string, subnet *macvlanv1.MacvlanSubnet) (*macvlanv1.MacvlanSubnet, error) {
		var err error
		var message string

		subnet, err = onChange(key, subnet)
		if subnet == nil {
			// Macvlan subnet resource is likely deleting.
			return subnet, err
		}
		if err != nil {
			logrus.Warnf("%v", err)
			message = err.Error()
		}
		if subnet.Name == "" {
			return subnet, err
		}

		if subnet.Status.FailureMessage == message {
			// Avoid trigger the rate limit.
			if message != "" {
				time.Sleep(time.Second * 5)
			}
			return subnet, err
		}

		err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
			subnet, err := h.macvlanSubnets.Get(macvlanv1.MacvlanSubnetNamespace, subnet.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			subnet = subnet.DeepCopy()
			if message != "" {
				// can assume an update is failing
				subnet.Status.Phase = macvlanSubnetFailedPhase
			}
			subnet.Status.FailureMessage = message

			_, err = h.macvlanSubnets.UpdateStatus(subnet)
			return err
		})
		if err != nil {
			logrus.Errorf("Error recording macvlan subnet config [%s] failure message: %v", subnet.Name, err)
		}
		return subnet, err
	}
}

func (h *handler) onMacvlanSubnetRemoved(s string, subnet *macvlanv1.MacvlanSubnet) (*macvlanv1.MacvlanSubnet, error) {
	if subnet == nil || subnet.Name == "" {
		return subnet, nil
	}
	return subnet, nil
}

func (h *handler) onMacvlanSubnetChanged(
	_ string, subnet *macvlanv1.MacvlanSubnet,
) (*macvlanv1.MacvlanSubnet, error) {
	if subnet == nil {
		return nil, nil
	}
	if subnet.Name == "" || subnet.DeletionTimestamp != nil {
		return subnet, nil
	}

	switch subnet.Status.Phase {
	case macvlanSubnetActivePhase:
		return h.updateMacvlanSubnet(subnet)
	default:
		return h.createMacvlanSubnet(subnet)
	}
}

func (h *handler) createMacvlanSubnet(subnet *macvlanv1.MacvlanSubnet) (*macvlanv1.MacvlanSubnet, error) {
	logrus.Infof("Create macvlan subnet [%v]", subnet.Name)
	// Update macvlan subnet labels and set status phase to pending.
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		result, err := h.macvlanSubnets.Get(macvlanv1.MacvlanSubnetNamespace, subnet.Name, metav1.GetOptions{})
		if err != nil {
			logrus.Debugf("Failed to get latest version of subnet: %v", err)
			return err
		}
		result = result.DeepCopy()
		if result.Labels == nil {
			result.Labels = make(map[string]string)
		}
		result.Labels["master"] = result.Spec.Master
		result.Labels["vlan"] = fmt.Sprintf("%v", result.Spec.VLAN)
		result.Labels["mode"] = result.Spec.Mode
		if result.Spec.Gateway == nil {
			gatewayIP, err := ipcalc.GetDefaultGateway(result.Spec.CIDR)
			if err != nil {
				return fmt.Errorf("failed to get macvlan subnet default gateway IP: %w", err)
			}
			result.Spec.Gateway = gatewayIP
		}
		result, err = h.macvlanSubnets.Update(result)
		if err != nil {
			logrus.Warnf("Failed to update subnet %q: %v", subnet.Name, err)
			return err
		}
		logrus.Infof("Updated macvlan subnet label %q: %v", subnet.Name, result.Labels)
		subnet = result
		return nil
	})
	if err != nil {
		return subnet, fmt.Errorf("createSubnet: failed to update label and gateway of subnet: %w", err)
	}

	// Add the gateway ip to syncmap.
	if subnet.Spec.Gateway == nil {
		return subnet, fmt.Errorf("createSubnet: subnet %q gateway should not empty", subnet.Name)
	}

	// TODO: Gateway IP conflic check.

	// Update the macvlan subnet status phase to active.
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		result, err := h.macvlanSubnets.Get(macvlanv1.MacvlanSubnetNamespace, subnet.Name, metav1.GetOptions{})
		if err != nil {
			logrus.Warnf("Failed to get latest version of subnet: %v", err)
			return err
		}
		result = result.DeepCopy()
		result.Status.Phase = macvlanSubnetActivePhase
		result.Status.UsedIP = append(result.Status.UsedIP, macvlanv1.IPRange{
			RangeStart: result.Spec.Gateway,
			RangeEnd:   result.Spec.Gateway,
		})
		result, err = h.macvlanSubnets.UpdateStatus(result)
		if err != nil {
			return err
		}
		subnet = result
		return nil
	})
	if err != nil {
		return subnet, fmt.Errorf("createSubnet: failed to update status of subnet: %w", err)
	}
	return subnet, nil
}

func (h *handler) updateMacvlanSubnet(subnet *macvlanv1.MacvlanSubnet) (*macvlanv1.MacvlanSubnet, error) {
	// Update macvlanip count of the subnet by updating the subnet label.
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		result, err := h.macvlanSubnets.Get(macvlanv1.MacvlanSubnetNamespace, subnet.Name, metav1.GetOptions{})
		if err != nil {
			logrus.Debugf("Failed to get latest version of subnet: %v", err)
			return err
		}
		result = result.DeepCopy()
		if result.Annotations == nil {
			result.Annotations = make(map[string]string)
		}

		// Get the pod count.
		pods, err := h.pods.List("", labels.SelectorFromSet(map[string]string{
			"subnet": result.Name,
		}))
		if err != nil {
			logrus.Debugf("Failed to get pod list of subnet %q: %v", result.Name, err)
			return err
		}
		count := fmt.Sprintf("%v", len(pods))
		if result.Annotations[subnetMacvlanIPCountAnnotation] == count {
			return nil
		}
		result.Annotations[subnetMacvlanIPCountAnnotation] = count

		result, err = h.macvlanSubnets.Update(result)
		if err != nil {
			logrus.Warnf("Failed to update subnet ip count: %v", err)
			return err
		}
		subnet = result
		return nil
	})
	if err != nil {
		return subnet, fmt.Errorf("updateSubnet: failed to update ip count of subnet %q: %v", subnet.Name, err)
	}

	// Sync the subnet every 10 secs.
	h.macvlansubnetEnqueueAfter(subnet.Namespace, subnet.Name, time.Second*10)
	return subnet, nil
}