package registereddomain_test

import (
	"testing"

	"github.com/banyansecurity/terraform-banyan-provider/client/registereddomain"
	"github.com/banyansecurity/terraform-banyan-provider/client/testutil"
	"github.com/stretchr/testify/assert"
)

func Test_RD_create_read_delete(t *testing.T) {

	reqBody := registereddomain.RegisteredDomainRequest{
		RegisteredDomainInfo: registereddomain.RegisteredDomainInfo{
			Name:        "test.bnntest.com",
			ClusterName: "cluster1",
			Cname:       "gke-usw1-at01.infra.bnntest.com",
			Description: "test me new",
		},
	}

	client, err := testutil.GetClientHolderForTest()
	assert.NoError(t, err, "Expected to not get an error here")

	//create record
	got, err := client.RegisteredDomain.Create(reqBody)
	if err != nil {
		t.Fatal(err)
	}

	//get created record info
	resp, err := client.RegisteredDomain.Get(got.ID)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, resp.ClusterName, reqBody.ClusterName)
	assert.Equal(t, resp.Cname, reqBody.Cname)
	assert.Equal(t, resp.Description, reqBody.Description)

	//delete create record
	err = client.RegisteredDomain.Delete(resp.ID)
	if err != nil {
		t.Fatal(err)
	}

}
