package apikey_test

import (
	"github.com/banyansecurity/terraform-banyan-provider/client/apikey"
	"github.com/banyansecurity/terraform-banyan-provider/client/testutil"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_Create(t *testing.T) {
	want := apikey.Post{
		Name:        "goclient-test",
		Description: "goclient-test",
		Scope:       "satellite",
	}
	client, err := testutil.GetClientHolderForTest()
	assert.NoError(t, err, "Expected to not get an error here")
	got, err := client.ApiKey.Create(want)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, got.Name, want.Name)
	assert.Equal(t, got.Description, want.Description)
	assert.Equal(t, got.Scope, want.Scope)
}

func Test_Get(t *testing.T) {
	want := apikey.Post{
		Name:        "goclient-test",
		Description: "goclient-test",
		Scope:       "satellite",
	}
	client, err := testutil.GetClientHolderForTest()
	assert.NoError(t, err, "Expected to not get an error here")
	got, err := client.ApiKey.Create(want)
	assert.NoError(t, err, "expected no error here")
	assert.Equal(t, got.Name, want.Name)
}

func Test_Delete(t *testing.T) {
	want := apikey.Data{
		ID:          "",
		OrgID:       "",
		Name:        "goclient-test",
		Secret:      "",
		Description: "goclient-test",
		Scope:       "satellite",
		CreatedBy:   "",
		UpdatedBy:   "",
	}
	client, err := testutil.GetClientHolderForTest()
	assert.NoError(t, err, "Expected to not get an error here")
	data, err := client.ApiKey.Get(want.Name)
	if err != nil {
		t.Fatal(err)
	}
	err = client.ApiKey.Delete(data.Name)
	if err != nil {
		t.Fatal(err)
	}
}
