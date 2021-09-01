package policy_test

import (
	"log"
	"os"
	"testing"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/policy"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
)

func Test_GetNonexistentService(t *testing.T) {
	err := godotenv.Load("../../.env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	emptyPolicy := policy.GetPolicy{}

	testhost := os.Getenv("BANYAN_HOST")
	testRefreshToken := os.Getenv("BANYAN_REFRESH_TOKEN")
	client, err := client.NewClientHolder(testhost, testRefreshToken)
	assert.NoError(t, err, "Expected to not get an error here")
	policy, ok, err := client.Policy.Get("heh")
	assert.NoError(t, err, "expected no error here")
	assert.False(t, ok, "expected to get a value here")
	assert.Equal(t, emptyPolicy, policy, "expected to get service x")
}

// https://dev05.console.bnntest.com/api/v1/security_policies?PolicyID=

func Test_GetExistingPolicy(t *testing.T) {
	err := godotenv.Load("../../.env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	emptyPolicy := policy.GetPolicy{}
	emptyPolicy.CreatedBy = "me"

	testhost := os.Getenv("BANYAN_HOST")
	testRefreshToken := os.Getenv("BANYAN_REFRESH_TOKEN")
	client, err := client.NewClientHolder(testhost, testRefreshToken)
	assert.NoError(t, err, "Expected to not get an error here")
	policy, ok, err := client.Policy.Get("dc612429-e8cf-4a0c-89b4-a41f14eb58bd")
	assert.NoError(t, err, "expected no error here")
	assert.True(t, ok, "expected to get a value here")
	assert.NotEqual(t, emptyPolicy, policy, "expected to get service x")
}

func Test_CreatePolicy(t *testing.T) {
	err := godotenv.Load("../../.env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	testhost := os.Getenv("BANYAN_HOST")
	testRefreshToken := os.Getenv("BANYAN_REFRESH_TOKEN")
	client, err := client.NewClientHolder(testhost, testRefreshToken)
	if err != nil {
		t.Fatalf("%+v", err)
	}
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
	resultOfGet, ok, err := client.Policy.Get(resultOfCreate.PolicyID)
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
	err := godotenv.Load("../../.env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	testhost := os.Getenv("BANYAN_HOST")
	testRefreshToken := os.Getenv("BANYAN_REFRESH_TOKEN")
	client, err := client.NewClientHolder(testhost, testRefreshToken)
	if err != nil {
		t.Fatalf("%+v", err)
	}
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
	_, ok, err := client.Policy.Get(createdPolicy.PolicyID)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	if !ok {
		t.Fatal("expected to find policy")
	}
	err = client.Policy.Delete(createdPolicy.PolicyID)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	_, ok, err = client.Policy.Get(createdPolicy.PolicyID)
	if err != nil {
		t. Fatalf("%+v", err)
	}
	assert.False(t, ok, "expected to not find the policy here")
}
