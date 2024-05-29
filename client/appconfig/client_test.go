package appconfig_test

import (
	"testing"

	"github.com/banyansecurity/terraform-banyan-provider/client/appconfig"
	"github.com/banyansecurity/terraform-banyan-provider/client/testutil"
	"github.com/stretchr/testify/assert"
)

var trueValue = true

var want = appconfig.AppConfigRecord{
	NRPTConfig: true,
}

var req = appconfig.AppConfigRequest{
	NRPTConfig: &trueValue,
}

func Test_Create(t *testing.T) {

	client, err := testutil.GetClientHolderForTest()

	assert.NoError(t, err, "Expected to not get an error here")

	got, err := client.AppConfig.Create(req)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, got.Data.NRPTConfig, want.NRPTConfig)
}

func Test_Get(t *testing.T) {
	client, err := testutil.GetClientHolderForTest()

	assert.NoError(t, err, "Expected to not get an error here")

	got, err := client.AppConfig.Get("")

	assert.NoError(t, err, "expected no error here")
	assert.Equal(t, got.Data.NRPTConfig, want.NRPTConfig)
}