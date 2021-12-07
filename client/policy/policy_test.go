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
	policy, ok, err := client.Policy.Get("heh")
	assert.NoError(t, err, "expected no error here")
	assert.False(t, ok, "expected to get a value here")

	assert.Equal(t, emptyPolicy, policy, "expected to get service x")
}

func Test_GetExistingPolicy(t *testing.T) {
	client, err := testutil.GetClientHolderForTest()
	assert.NoError(t, err, "Expected to not get an error here")
	emptyPolicy := policy.GetPolicy{}
	emptyPolicy.CreatedBy = "me"

	policy, ok, err := client.Policy.Get("9ddf21be-2db3-42f6-aa77-2d1a61931278")
	assert.NoError(t, err, "expected no error here")
	assert.True(t, ok, "expected to get a value here")
	assert.NotEqual(t, emptyPolicy, policy, "expected to get service x")
}

func Test_CreatePolicy(t *testing.T) {
	client, err := testutil.GetClientHolderForTest()
	assert.NoError(t, err, "Expected to not get an error here")
	testPolicy := policy.CreatePolicy{
		APIVersion: "rbac.banyanops.com/v1",
		Kind:       "BanyanPolicy",
		Metadata: policy.Metadata{
			Description: "tf-test",
			Name:        "tf-automation-test",
			Tags: policy.Tags{
				Template: "USER",
			},
		},
		Type: "USER",
		Spec: policy.Spec{
			Access: []policy.Access{
				{
					Roles: []string{"ROLE1"},
					Rules: policy.Rules{
						Conditions: policy.Conditions{
							TrustLevel: "HIGH",
						},
						L7Access: []policy.L7Access{
							{Actions: []string{"*"}, Resources: []string{"*"}},
						},
					},
				},
			},
			Exception: policy.Exception{
				SourceAddress: []string{},
			},
			Options: policy.Options{
				DisableTLSClientAuthentication: true,
				L7Protocol:                     "http",
			},
		},
	}

	resultOfCreate, err := client.Policy.Create(testPolicy)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	resultOfGet, ok, err := client.Policy.Get(resultOfCreate.ID)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	if !ok {
		t.Fatalf("Didn't find the policy")
	}
	// these will potentially conflict
	resultOfCreate.LastUpdatedAt = 0
	resultOfGet.LastUpdatedAt = 0
	assert.Equal(t, resultOfCreate, resultOfGet)
}

func Test_Delete(t *testing.T) {
	client, err := testutil.GetClientHolderForTest()
	assert.NoError(t, err, "Expected to not get an error here")
	testPolicy := policy.CreatePolicy{
		APIVersion: "rbac.banyanops.com/v1",
		Kind:       "BanyanPolicy",
		Metadata: policy.Metadata{
			Description: "tf-test-delete",
			Name:        "tf-automation-test-delete",
			Tags: policy.Tags{
				Template: "USER",
			},
		},
		Type: "USER",
		Spec: policy.Spec{
			Access: []policy.Access{
				{
					Roles: []string{"ROLE1"},
					Rules: policy.Rules{
						Conditions: policy.Conditions{
							TrustLevel: "HIGH",
						},
						L7Access: []policy.L7Access{
							{Actions: []string{"*"}, Resources: []string{"*"}},
						},
					},
				},
			},
			Exception: policy.Exception{
				SourceAddress: []string{},
			},
			Options: policy.Options{
				DisableTLSClientAuthentication: true,
				L7Protocol:                     "http",
			},
		},
	}
	createdPolicy, err := client.Policy.Create(testPolicy)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	_, ok, err := client.Policy.Get(createdPolicy.ID)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	if !ok {
		t.Fatal("expected to find policy")
	}
	err = client.Policy.Delete(createdPolicy.ID)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	_, ok, err = client.Policy.Get(createdPolicy.ID)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	assert.False(t, ok, "expected to not find the policy here")
}
