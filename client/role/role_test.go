package role_test

import (
	"testing"

	"github.com/banyansecurity/terraform-banyan-provider/client/role"
	"github.com/banyansecurity/terraform-banyan-provider/client/testutil"
	"github.com/stretchr/testify/assert"
)

func Test_GetNonexistentRole(t *testing.T) {
	emptyRole := role.GetRole{}
	client, err := testutil.GetClientHolderForTest()
	assert.NoError(t, err, "Expected to not get an error here")
	role, ok, err := client.Role.Get("heh")
	assert.NoError(t, err, "expected no error here")
	assert.False(t, ok, "expected to get a value here")

	assert.Equal(t, emptyRole, role, "expected to get service x")
}

func Test_GetExistingRole(t *testing.T) {
	client, err := testutil.GetClientHolderForTest()
	assert.NoError(t, err, "Expected to not get an error here")
	emptyRole := role.GetRole{}
	emptyRole.CreatedBy = "me"

	role, ok, err := client.Role.Get("3746e045-aa73-4fd3-96c5-a7ed893d3eaa")
	assert.NoError(t, err, "expected no error here")
	assert.True(t, ok, "expected to get a value here")
	assert.NotEqual(t, emptyRole, role, "expected to get service x")
}

func Test_CreateRole(t *testing.T) {
	client, err := testutil.GetClientHolderForTest()
	assert.NoError(t, err, "Expected to not get an error here")
	testRole := role.CreateRole{
		APIVersion: "rbac.banyanops.com/v1",
		Kind:       "BanyanRole",
		Metadata: role.Metadata{
			Description: "tf-test",
			Name:        "tf-automation-test-create",
			Tags: role.Tags{
				Template: "USER",
			},
		},
		Type: "USER",
		Spec: role.Spec{
			DeviceOwnership: []string{"Corporate Dedicated", "Employee Owned", "Corporate Shared", "Other"},
			Group:           []string{"group1", "group2"},
			Email:           []string{"john@john.com"},
			KnownDeviceOnly: true,
			MDMPresent:      true,
			Platform:        []string{"Windows", "Linux", "Android", "Unregistered", "iOS", "macOS"},
		},
	}

	resultOfCreate, err := client.Role.Create(testRole)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	resultOfGet, ok, err := client.Role.Get(resultOfCreate.ID)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	if !ok {
		t.Fatalf("Didn't find the role")
	}
	// these will potentially conflict
	resultOfCreate.LastUpdatedAt = 0
	resultOfGet.LastUpdatedAt = 0
	assert.Equal(t, resultOfCreate, resultOfGet)
}

func Test_Delete(t *testing.T) {
	client, err := testutil.GetClientHolderForTest()
	assert.NoError(t, err, "Expected to not get an error here")
	testRole := role.CreateRole{
		APIVersion: "rbac.banyanops.com/v1",
		Kind:       "BanyanRole",
		Metadata: role.Metadata{
			Description: "tf-test-delete",
			Name:        "tf-automation-test-delete",
			Tags: role.Tags{
				Template: "USER",
			},
		},
		Type: "USER",
		Spec: role.Spec{
			DeviceOwnership: []string{"Corporate Dedicated", "Employee Owned", "Corporate Shared", "Other"},
			Group:           []string{"group1", "group2"},
			Email:           []string{"john@john.com"},
			KnownDeviceOnly: true,
			MDMPresent:      true,
			Platform:        []string{"Windows", "Linux", "Android", "Unregistered", "iOS", "macOS"},
		},
	}
	createdRole, err := client.Role.Create(testRole)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	_, ok, err := client.Role.Get(createdRole.ID)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	if !ok {
		t.Fatal("expected to find role")
	}
	err = client.Role.Delete(createdRole.ID)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	_, ok, err = client.Role.Get(createdRole.ID)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	assert.False(t, ok, "expected to not find the role here")
}
