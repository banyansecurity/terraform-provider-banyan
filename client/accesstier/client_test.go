package accesstier

import (
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
	"github.com/stretchr/testify/assert"
	"testing"
)

func GetClientForTest() (accessTierClient *AccessTier) {
	restClient, err := restclient.New(client.GetBanyanHostUrl(), client.GetApiKey())
	if err != nil {
		return
	}

	c := AccessTier{restClient: restClient}
	return &c
}

func TestAccessTierGet(t *testing.T) {
	type testCase struct {
		Name string

		AccessTier *AccessTier

		Id string

		ExpectedAtInfo AccessTierInfo
		ExpectedErr    error
	}

	validate := func(t *testing.T, tc *testCase) {
		t.Run(tc.Name, func(t *testing.T) {

			actualAtInfo, actualErr := tc.AccessTier.Get(tc.Id)

			assert.Equal(t, tc.ExpectedAtInfo.Name, actualAtInfo.Name)
			assert.Equal(t, tc.ExpectedErr, actualErr)
		})
	}

	tc := testCase{
		Name:       "Get pre-existing",
		AccessTier: GetClientForTest(),
		Id:         "b29f24db-fc3a-4eb4-880b-8fb1245e13d3",
		ExpectedAtInfo: AccessTierInfo{
			Name: "at-recreate-1",
		},
		ExpectedErr: nil,
	}

	validate(t, &tc)
}

func TestAccessTierCreate(t *testing.T) {
	type testCase struct {
		Name string

		AccessTier *AccessTier

		Post AccessTierPost

		ExpectedAtInfo AccessTierInfo
		ExpectedErr    error
	}

	post := AccessTierPost{
		Name:             "goclient-testcase-create",
		Address:          "test.somedomain.com",
		Domains:          []string{"somedomain.com"},
		TunnelSatellite:  &AccessTierTunnelInfoPost{},
		TunnelEnduser:    &AccessTierTunnelInfoPost{},
		ClusterName:      "tortoise",
		DisableSnat:      false,
		SrcNATCIDRRange:  "",
		Description:      "test case resource for terraform go client",
		ApiKeyId:         "31ec7fc7-08a1-4f4a-9e35-b63d034fb407",
		DeploymentMethod: "docker",
	}

	validate := func(t *testing.T, tc *testCase) {
		t.Run(tc.Name, func(t *testing.T) {
			actualAtInfo, actualErr := tc.AccessTier.Create(tc.Post)

			assert.Equal(t, tc.ExpectedAtInfo.Name, actualAtInfo.Name)
			assert.Equal(t, tc.ExpectedAtInfo.Address, actualAtInfo.Address)
			assert.Equal(t, tc.ExpectedAtInfo.APIKeyID, actualAtInfo.APIKeyID)
			assert.Equal(t, tc.ExpectedErr, actualErr)
		})
	}

	validate(t, &testCase{
		Name:       "",
		AccessTier: GetClientForTest(),
		Post:       post,
		ExpectedAtInfo: AccessTierInfo{
			Name:     post.Name,
			Address:  post.Address,
			APIKeyID: post.ApiKeyId,
		},
		ExpectedErr: nil,
	})
}

func TestAccessTierGetLocalConfig(t *testing.T) {
	type testCase struct {
		Name string

		AccessTier *AccessTier

		N string

		ExpectedErr error
	}

	expectedShieldAddress := "test.somedomain.com"
	expectedSiteAddress := "35.247.44.2:1200"

	validate := func(t *testing.T, tc *testCase) {
		t.Run(tc.Name, func(t *testing.T) {
			actualAtLocalConf, actualErr := tc.AccessTier.GetLocalConfig(tc.N)

			assert.Equal(t, expectedShieldAddress, *actualAtLocalConf.BaseParameters.SiteAddress)
			assert.Equal(t, expectedSiteAddress, *actualAtLocalConf.BaseParameters.ShieldAddress)
			assert.Equal(t, tc.ExpectedErr, actualErr)
		})
	}

	validate(t, &testCase{
		Name:        "",
		AccessTier:  GetClientForTest(),
		N:           "goclient-testcase-create",
		ExpectedErr: nil,
	})
}
