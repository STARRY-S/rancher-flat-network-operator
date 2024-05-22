package ipcalc

import (
	"net"
	"testing"

	macvlanv1 "github.com/cnrancher/flat-network-operator/pkg/apis/macvlan.cluster.cattle.io/v1"
	"gotest.tools/v3/assert"
)

func Test_IPIncrease(t *testing.T) {
	var ip1, ip2 net.IP
	ip1 = net.IPv4(192, 168, 1, 1)
	ip2 = net.IPv4(192, 168, 1, 2)
	IPIncrease(ip1)
	assert.DeepEqual(t, ip1, ip2)

	ip1 = net.IPv4(192, 168, 1, 255)
	ip2 = net.IPv4(192, 168, 2, 0)
	IPIncrease(ip1)
	assert.DeepEqual(t, ip1, ip2)
}

func Test_CalcDefaultGateway(t *testing.T) {
	ip, _ := GetDefaultGateway("192.168.1.0/24")
	assert.DeepEqual(t, net.ParseIP("192.168.1.1"), ip)
	ip, _ = GetDefaultGateway("")
	assert.Check(t, ip == nil)
}

func Test_IPInRanges(t *testing.T) {
	var ip = net.ParseIP("10.0.0.1")
	if !IPInRanges(ip, nil) {
		t.Fatal("failed")
	}
	if !IPInRanges(ip, []macvlanv1.IPRange{}) {
		t.Fatal("failed")
	}

	var ipRanges = []macvlanv1.IPRange{
		{
			RangeStart: net.ParseIP("10.0.0.1"),
			RangeEnd:   net.ParseIP("10.0.0.1"),
		},
	}
	if !IPInRanges(ip, ipRanges) {
		t.Fatal("failed")
	}

	ipRanges = []macvlanv1.IPRange{
		{
			RangeStart: net.ParseIP("10.0.0.1"),
			RangeEnd:   net.ParseIP("10.0.0.255"),
		},
	}
	if !IPInRanges(ip, ipRanges) {
		t.Fatal("failed")
	}

	ip = net.ParseIP("10.0.0.100")
	if !IPInRanges(ip, ipRanges) {
		t.Fatal("failed")
	}

	ip = net.ParseIP("192.168.0.1")
	if IPInRanges(ip, ipRanges) {
		t.Fatal("failed")
	}
}

func Test_IPNotUsed(t *testing.T) {
	var ip = net.ParseIP("10.0.0.1")
	if !IPNotUsed(ip, nil) {
		t.Fatal("failed")
	}
	if !IPNotUsed(ip, []macvlanv1.IPRange{}) {
		t.Fatal("failed")
	}

	var usedRanges = []macvlanv1.IPRange{
		{
			RangeStart: net.ParseIP("10.0.0.1"),
			RangeEnd:   net.ParseIP("10.0.0.1"),
		},
	}
	if IPNotUsed(ip, usedRanges) {
		t.Fatal("failed")
	}

	usedRanges = []macvlanv1.IPRange{
		{
			RangeStart: net.ParseIP("10.0.0.100"),
			RangeEnd:   net.ParseIP("10.0.0.200"),
		},
	}
	if !IPNotUsed(ip, usedRanges) {
		t.Fatal("failed")
	}
	ip = net.ParseIP("10.0.0.110")
	if IPNotUsed(ip, usedRanges) {
		t.Fatal("failed")
	}
}

func Test_GetAvailableIP(t *testing.T) {
	ip, err := GetAvailableIP("10.0.0.0/24", nil, nil)
	assert.NilError(t, err)
	assert.DeepEqual(t, ip, net.ParseIP("10.0.0.1"))

	ip, err = GetAvailableIP("10.0.0.0/24", []macvlanv1.IPRange{}, []macvlanv1.IPRange{})
	assert.NilError(t, err)
	assert.DeepEqual(t, ip, net.ParseIP("10.0.0.1"))

	ip, _ = GetAvailableIP(
		"10.0.0.0/24",
		[]macvlanv1.IPRange{
			{
				RangeStart: net.ParseIP("10.0.0.100"),
				RangeEnd:   net.ParseIP("10.0.0.200"),
			},
		},
		[]macvlanv1.IPRange{},
	)
	assert.DeepEqual(t, ip, net.ParseIP("10.0.0.100"))

	ip, _ = GetAvailableIP(
		"10.0.0.0/24",
		[]macvlanv1.IPRange{
			{
				RangeStart: net.ParseIP("10.0.0.100"),
				RangeEnd:   net.ParseIP("10.0.0.200"),
			},
			{
				RangeStart: net.ParseIP("10.0.0.210"),
				RangeEnd:   net.ParseIP("10.0.0.220"),
			},
		},
		[]macvlanv1.IPRange{
			{
				RangeStart: net.ParseIP("10.0.0.100"),
				RangeEnd:   net.ParseIP("10.0.0.200"),
			},
		},
	)
	assert.DeepEqual(t, ip, net.ParseIP("10.0.0.210"))

	ip, _ = GetAvailableIP(
		"10.0.0.0/24",
		[]macvlanv1.IPRange{
			{
				RangeStart: net.ParseIP("10.0.0.100"),
				RangeEnd:   net.ParseIP("10.0.0.200"),
			},
			{
				RangeStart: net.ParseIP("10.0.0.210"),
				RangeEnd:   net.ParseIP("10.0.0.220"),
			},
		},
		[]macvlanv1.IPRange{
			{
				RangeStart: net.ParseIP("10.0.0.100"),
				RangeEnd:   net.ParseIP("10.0.0.200"),
			},
			{
				RangeStart: net.ParseIP("10.0.0.210"),
				RangeEnd:   net.ParseIP("10.0.0.210"),
			},
		},
	)
	assert.DeepEqual(t, ip, net.ParseIP("10.0.0.211"))

	ip, _ = GetAvailableIP(
		"10.0.0.0/8",
		[]macvlanv1.IPRange{
			{
				RangeStart: net.ParseIP("10.255.255.254"),
				RangeEnd:   net.ParseIP("10.255.255.254"),
			},
		},
		[]macvlanv1.IPRange{},
	)
	assert.DeepEqual(t, ip, net.ParseIP("10.255.255.254"))

	ip, err = GetAvailableIP(
		"10.0.0.0/8",
		[]macvlanv1.IPRange{
			{
				RangeStart: net.ParseIP("10.255.255.254"),
				RangeEnd:   net.ParseIP("10.255.255.254"),
			},
		},
		[]macvlanv1.IPRange{
			{
				RangeStart: net.ParseIP("10.255.255.254"),
				RangeEnd:   net.ParseIP("10.255.255.254"),
			},
		},
	)
	assert.ErrorIs(t, err, ErrNoAvailableIP)
	assert.Equal(t, len(ip), 0)

	ip, err = GetAvailableIP(
		"10.0.0.0/8",
		[]macvlanv1.IPRange{},
		[]macvlanv1.IPRange{
			{
				RangeStart: net.ParseIP("10.0.0.0"),
				RangeEnd:   net.ParseIP("10.255.255.254"),
			},
		},
	)
	assert.ErrorIs(t, err, ErrNoAvailableIP)
	assert.Equal(t, len(ip), 0)
}

func Test_AddCIDRSuffix(t *testing.T) {
	ip := net.ParseIP("192.168.1.12")
	c := AddCIDRSuffix(ip, "192.168.1.0/24")
	assert.Equal(t, "192.168.1.12/24", c)

	ip = net.ParseIP("10.0.0.1")
	c = AddCIDRSuffix(ip, "10.0.0.0/8")
	assert.Equal(t, "10.0.0.1/8", c)

	ip = net.ParseIP("172.31.1.100")
	c = AddCIDRSuffix(ip, "172.16.0.0/16")
	assert.Equal(t, "172.31.1.100/16", c)

	ip = net.ParseIP("172.31.1.100")
	c = AddCIDRSuffix(ip, "172.16.0.0")
	assert.Equal(t, "172.31.1.100/32", c)
}