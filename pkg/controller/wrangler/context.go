package wrangler

import (
	"context"
	"fmt"

	macvlanscheme "github.com/cnrancher/flat-network-operator/pkg/generated/clientset/versioned/scheme"
	"github.com/cnrancher/flat-network-operator/pkg/generated/controllers/apps"
	appsv1 "github.com/cnrancher/flat-network-operator/pkg/generated/controllers/apps/v1"
	"github.com/cnrancher/flat-network-operator/pkg/generated/controllers/batch"
	batchv1 "github.com/cnrancher/flat-network-operator/pkg/generated/controllers/batch/v1"
	"github.com/cnrancher/flat-network-operator/pkg/generated/controllers/core"
	corecontroller "github.com/cnrancher/flat-network-operator/pkg/generated/controllers/core/v1"
	macvlan "github.com/cnrancher/flat-network-operator/pkg/generated/controllers/macvlan.cluster.cattle.io"
	macvlanv1 "github.com/cnrancher/flat-network-operator/pkg/generated/controllers/macvlan.cluster.cattle.io/v1"
	"github.com/cnrancher/flat-network-operator/pkg/generated/controllers/networking.k8s.io"
	networkingv1 "github.com/cnrancher/flat-network-operator/pkg/generated/controllers/networking.k8s.io/v1"
	"github.com/rancher/wrangler/v2/pkg/start"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
)

type Context struct {
	RESTConfig *rest.Config

	Macvlan    macvlanv1.Interface
	Core       corecontroller.Interface
	Apps       appsv1.Interface
	Networking networkingv1.Interface
	Batch      batchv1.Interface
	Recorder   record.EventRecorder

	starters []start.Starter
}

func NewContext(
	restCfg *rest.Config,
) (*Context, error) {
	// panic on error
	macvlan := macvlan.NewFactoryFromConfigOrDie(restCfg)
	core := core.NewFactoryFromConfigOrDie(restCfg)
	apps := apps.NewFactoryFromConfigOrDie(restCfg)
	networking := networking.NewFactoryFromConfigOrDie(restCfg)
	batch := batch.NewFactoryFromConfigOrDie(restCfg)

	clientSet, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build clientset: %w", err)
	}

	utilruntime.Must(macvlanscheme.AddToScheme(scheme.Scheme))
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(logrus.Warnf)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: clientSet.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: "flat-network-operarto"})

	c := &Context{
		RESTConfig: restCfg,
		Macvlan:    macvlan.Macvlan().V1(),
		Core:       core.Core().V1(),
		Apps:       apps.Apps().V1(),
		Networking: networking.Networking().V1(),
		Batch:      batch.Batch().V1(),
		Recorder:   recorder,
	}
	c.starters = append(c.starters, macvlan, core, apps, networking, batch)
	return c, nil
}

func (c *Context) Start(ctx context.Context, worker int) error {
	return start.All(ctx, worker, c.starters...)
}