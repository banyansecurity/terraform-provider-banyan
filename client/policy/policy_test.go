package policy_test

import (
	"testing"

	"github.com/banyansecurity/terraform-banyan-provider/client/policy"
	"github.com/banyansecurity/terraform-banyan-provider/client/testutil"
	"github.com/stretchr/testify/assert"
)

func Test_GetNonexistentService(t *testing.T) {
	emptyPolicy := policy.GetPolicy{}
	client, err := testutil.GetClientHolderForTest()
	assert.NoError(t, err, "Expected to not get an error here")
	myPolicy, err := client.Policy.Get("heh")
	assert.NoError(t, err, "expected no error here")
	assert.Equal(t, emptyPolicy, myPolicy, "expected to get service x")
}

func Test_GetExistingPolicy(t *testing.T) {
	client, err := testutil.GetClientHolderForTest()
	assert.NoError(t, err, "Expected to not get an error here")
	emptyPolicy := policy.GetPolicy{}
	emptyPolicy.CreatedBy = "me"
	myPolicy, err := client.Policy.Get("9ddf21be-2db3-42f6-aa77-2d1a61931278")
	assert.NoError(t, err, "expected no error here")
	assert.NotEqual(t, emptyPolicy, myPolicy, "expected to get service x")
}
