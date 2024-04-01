package accesstiregroup_test

import (
	"testing"

	"github.com/banyansecurity/terraform-banyan-provider/client/accesstier"
	"github.com/banyansecurity/terraform-banyan-provider/client/accesstiregroup"
	"github.com/banyansecurity/terraform-banyan-provider/client/testutil"
	"github.com/stretchr/testify/assert"
)

var want = accesstiregroup.AccessTierGroupPost{
	Name:        "new-nnm-88w",
	Description: "testing-1",
	ClusterName: "cluster1",
	AdvancedSettings: accesstier.AccessTierLocalConfig{
		LoggingParameters: &accesstier.LoggingParameters{
			StatsD:        accesstier.BoolPtr(false),
			StatsDAddress: accesstier.StringPtr("127.0.0.1:8125"),
		},
	},
	TunnelConfig: &accesstier.AccessTierTunnelInfoPost{
		DNSSearchDomains: "",
		Domains:          []string{"test-1.com"},
		CIDRs:            []string{"198.169.0.1/24"},
		DNSEnabled:       false,
		UDPPortNumber:    16578,
	},
	SharedFQDN: "testing.com",
}

func Test_Create(t *testing.T) {

	client, err := testutil.GetClientHolderForTest()

	assert.NoError(t, err, "Expected to not get an error here")

	got, err := client.AccessTierGroup.Create(want)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, got.Name, want.Name)
	assert.Equal(t, got.ClusterName, want.ClusterName)
	assert.Equal(t, got.TunnelConfig.SharedFQDN, want.SharedFQDN)
}

func Test_Get(t *testing.T) {
	client, err := testutil.GetClientHolderForTest()

	assert.NoError(t, err, "Expected to not get an error here")

	got, err := client.AccessTierGroup.GetName(want.Name)

	assert.NoError(t, err, "expected no error here")
	assert.Equal(t, got.Name, want.Name)
}

func Test_Delete(t *testing.T) {
	client, err := testutil.GetClientHolderForTest()

	assert.NoError(t, err, "Expected to not get an error here")

	data, err := client.AccessTierGroup.Get(want.Name)
	if err != nil {
		t.Fatal(err)
	}

	err = client.ApiKey.Delete(data.ID)
	if err != nil {
		t.Fatal(err)
	}
}
