package satellite_test

import (
	"github.com/banyansecurity/terraform-banyan-provider/client/satellite"
	"github.com/banyansecurity/terraform-banyan-provider/client/testutil"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_CreatSatellite(t *testing.T) {
	client, err := testutil.GetClientHolderForTest()
	assert.NoError(t, err, "Expected to not get an error here")
	testSatellite := satellite.Info{
		Kind:       "BanyanConnector",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "attribute-based",
		Metadata: satellite.Metadata{
			Name:        "go-client-test",
			DisplayName: "go-client-test",
		},
		Spec: satellite.Spec{
			APIKeyID:  "lR_6G2cq11gQBfyT3gKg9nzaYomTiGVSWh_yh7xZ1yY",
			Keepalive: 1000,
			CIDRs:     []string{"10.0.0.1/24"},
			PeerAccessTiers: []satellite.PeerAccessTier{
				{
					Cluster:     "us-west",
					AccessTiers: []string{"us-west1"},
				},
			},
		},
	}
	got, err := client.Satellite.Create(testSatellite)
	if err != nil {
		return
	}
	want := satellite.SatelliteTunnelConfig{}
	AssertEqual(t, got, want)
}

func Test_GetExistingSatellite(t *testing.T) {
	client, err := testutil.GetClientHolderForTest()
	assert.NoError(t, err, "Expected to not get an error here")
	got, err := client.Satellite.Get("53bb4cdb-8118-4830-a10f-0c69e17d78e3")
	assert.NoError(t, err, "expected no error here")
	assert.NotEqual(t, got.ID, "")
}

func AssertEqual(t *testing.T, got satellite.SatelliteTunnelConfig, want satellite.SatelliteTunnelConfig) {
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("service.Spec{} mismatch (-want +got):\n%s", diff)
	}
}
