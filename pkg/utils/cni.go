package utils

import (
	"encoding/json"
	"fmt"

	"github.com/cnrancher/rancher-flat-network-operator/pkg/cni/types"
	"github.com/vishvananda/netlink"
)

func LoadCNINetConf(bytes []byte) (*types.NetConf, error) {
	n := &types.NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %w", err)
	}
	return n, nil
}

func SetPromiscOn(iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("failed to search iface %q: %w", iface, err)
	}

	if link.Attrs().Promisc != 1 {
		err = netlink.SetPromiscOn(link)
		if err != nil {
			return fmt.Errorf("netlink.SetPromiscOn failed on iface %q: %w", iface, err)
		}
	}
	return nil
}
