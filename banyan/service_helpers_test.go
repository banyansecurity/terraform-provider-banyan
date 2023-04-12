package banyan

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/banyansecurity/terraform-banyan-provider/client/policy"
	"github.com/banyansecurity/terraform-banyan-provider/client/role"

	"github.com/stretchr/testify/assert"

	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/banyansecurity/terraform-banyan-provider/client/servicetunnel"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// Returns service from JSON string
func ReadJSONServiceSpec(jsonSpec string) (svc service.GetServiceSpec, err error) {
	var createdServiceJson service.GetServicesJson
	err = json.Unmarshal([]byte(jsonSpec), &createdServiceJson)
	if err != nil {
		return
	}
	var createdSpec service.CreateService
	err = json.Unmarshal([]byte(jsonSpec), &createdSpec)
	if err != nil {
		return
	}
	createdServiceJson.CreateServiceSpec = createdSpec
	svc = service.MapToGetServiceSpec(createdServiceJson)
	return svc, err
}

func ReadJSONPolicySpec(jsonSpec string) (pol policy.Object, err error) {
	err = json.Unmarshal([]byte(jsonSpec), &pol)
	return pol, err
}

func AssertServiceSpecEqual(t *testing.T, got service.GetServiceSpec, want service.GetServiceSpec) {
	if diff := cmp.Diff(want.CreateServiceSpec, got.CreateServiceSpec); diff != "" {
		t.Errorf("service.Spec{} mismatch (-want +got):\n%s", diff)
	}
}

func AssertPolicySpecEqual(t *testing.T, got policy.Object, want policy.Object) {
	less := func(a, b string) bool { return a < b }

	if diff := cmp.Diff(want, got, cmpopts.SortSlices(less)); diff != "" {
		t.Errorf("service.Spec{} mismatch (-want +got):\n%s", diff)
	}
}

func AssertCreateRoleEqual(t *testing.T, got role.CreateRole, want role.CreateRole) {
	less := func(a, b string) bool { return a < b }

	if diff := cmp.Diff(want, got, cmpopts.SortSlices(less)); diff != "" {
		t.Errorf("role.Spec{} mismatch (-want +got):\n%s", diff)
	}
}

func AssertCreateServiceEqual(t *testing.T, got service.CreateService, want service.CreateService) {
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("service.Spec{} mismatch (-want +got):\n%s", diff)
	}
}

func AssertServiceTunnelEqual(t *testing.T, got servicetunnel.Info, want servicetunnel.Info) {
	less := func(a, b string) bool { return a < b }

	if diff := cmp.Diff(want, got, cmpopts.SortSlices(less)); diff != "" {
		t.Errorf("service.Spec{} mismatch (-want +got):\n%s", diff)
	}
}

// Asserts that the json string j is equal to the service spec in the API with id
func testAccCheckServiceAgainstJson(t *testing.T, j string, id *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		got, err := testAccClient.Service.Get(*id)
		if err != nil {
			return err
		}
		want, err := ReadJSONServiceSpec(j)
		if err != nil {
			return err
		}
		AssertServiceSpecEqual(t, got, want)
		return nil
	}
}

// Asserts that the json string j is equal to the policy spec in the API with id
func testAccCheckPolicyAgainstJson(t *testing.T, j string, id *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		got, err := testAccClient.Policy.Get(*id)
		if err != nil {
			return err
		}
		want, err := ReadJSONPolicySpec(j)
		if err != nil {
			return err
		}
		AssertPolicySpecEqual(t, got.UnmarshalledPolicy, want)
		return nil
	}
}

// Checks that the resource with the name resourceName exists and returns the role object from the Banyan API
func testAccCheckExistingService(resourceName string, bnnService *service.GetServiceSpec) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found %q", rs)
		}
		resp, err := testAccClient.Service.Get(rs.Primary.ID)
		if err != nil {
			return err
		}
		if resp.ServiceID != rs.Primary.ID {
			return fmt.Errorf("expected resource id %q got %q instead", resp.ServiceID, rs.Primary.ID)
		}
		*bnnService = resp
		return nil
	}
}

// Asserts using the API that the Spec.Backend.ConnectorName for the service was updated

// Uses the API to check that the service was destroyed
func testAccCheckServiceDestroy(t *testing.T, id *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		r, _ := testAccClient.AccessTier.Get(*id)
		assert.Equal(t, r.ID, "")
		return nil
	}
}
