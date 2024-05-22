/*
Copyright 2024 SUSE Rancher

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by main. DO NOT EDIT.

package fake

import (
	"context"

	v1 "github.com/cnrancher/flat-network-operator/pkg/apis/macvlan.cluster.cattle.io/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeMacvlanSubnets implements MacvlanSubnetInterface
type FakeMacvlanSubnets struct {
	Fake *FakeMacvlanV1
	ns   string
}

var macvlansubnetsResource = v1.SchemeGroupVersion.WithResource("macvlansubnets")

var macvlansubnetsKind = v1.SchemeGroupVersion.WithKind("MacvlanSubnet")

// Get takes name of the macvlanSubnet, and returns the corresponding macvlanSubnet object, and an error if there is any.
func (c *FakeMacvlanSubnets) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.MacvlanSubnet, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(macvlansubnetsResource, c.ns, name), &v1.MacvlanSubnet{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.MacvlanSubnet), err
}

// List takes label and field selectors, and returns the list of MacvlanSubnets that match those selectors.
func (c *FakeMacvlanSubnets) List(ctx context.Context, opts metav1.ListOptions) (result *v1.MacvlanSubnetList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(macvlansubnetsResource, macvlansubnetsKind, c.ns, opts), &v1.MacvlanSubnetList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1.MacvlanSubnetList{ListMeta: obj.(*v1.MacvlanSubnetList).ListMeta}
	for _, item := range obj.(*v1.MacvlanSubnetList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested macvlanSubnets.
func (c *FakeMacvlanSubnets) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(macvlansubnetsResource, c.ns, opts))

}

// Create takes the representation of a macvlanSubnet and creates it.  Returns the server's representation of the macvlanSubnet, and an error, if there is any.
func (c *FakeMacvlanSubnets) Create(ctx context.Context, macvlanSubnet *v1.MacvlanSubnet, opts metav1.CreateOptions) (result *v1.MacvlanSubnet, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(macvlansubnetsResource, c.ns, macvlanSubnet), &v1.MacvlanSubnet{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.MacvlanSubnet), err
}

// Update takes the representation of a macvlanSubnet and updates it. Returns the server's representation of the macvlanSubnet, and an error, if there is any.
func (c *FakeMacvlanSubnets) Update(ctx context.Context, macvlanSubnet *v1.MacvlanSubnet, opts metav1.UpdateOptions) (result *v1.MacvlanSubnet, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(macvlansubnetsResource, c.ns, macvlanSubnet), &v1.MacvlanSubnet{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.MacvlanSubnet), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeMacvlanSubnets) UpdateStatus(ctx context.Context, macvlanSubnet *v1.MacvlanSubnet, opts metav1.UpdateOptions) (*v1.MacvlanSubnet, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(macvlansubnetsResource, "status", c.ns, macvlanSubnet), &v1.MacvlanSubnet{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.MacvlanSubnet), err
}

// Delete takes name of the macvlanSubnet and deletes it. Returns an error if one occurs.
func (c *FakeMacvlanSubnets) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(macvlansubnetsResource, c.ns, name, opts), &v1.MacvlanSubnet{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeMacvlanSubnets) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(macvlansubnetsResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1.MacvlanSubnetList{})
	return err
}

// Patch applies the patch and returns the patched macvlanSubnet.
func (c *FakeMacvlanSubnets) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.MacvlanSubnet, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(macvlansubnetsResource, c.ns, name, pt, data, subresources...), &v1.MacvlanSubnet{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.MacvlanSubnet), err
}