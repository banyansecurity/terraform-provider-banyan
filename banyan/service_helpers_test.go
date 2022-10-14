package banyan

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// Returns service from JSON string
func ReadJSONServiceSpec(jsonSpec string) (err error, svc service.GetServiceSpec) {
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
	return
}

func AssertServiceSpecEqual(t *testing.T, got service.GetServiceSpec, want service.GetServiceSpec) {
	if diff := cmp.Diff(want.CreateServiceSpec, got.CreateServiceSpec); diff != "" {
		t.Errorf("service.Spec{} mismatch (-want +got):\n%s", diff)
	}
}

func AssertCreateServiceEqual(t *testing.T, got service.CreateService, want service.CreateService) {
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("service.Spec{} mismatch (-want +got):\n%s", diff)
	}
}

func testAccCheckAgainstJson(t *testing.T, path string, id *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		got, err := testAccClient.Service.Get(*id)
		if err != nil {
			return err
		}
		err, want := ReadJSONServiceSpec(path)
		if err != nil {
			return err
		}
		AssertServiceSpecEqual(t, got, want)
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
func testAccCheckServiceConnectorNameUpdated(bnnService *service.GetServiceSpec, connectorName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if connectorName != bnnService.CreateServiceSpec.Spec.Backend.ConnectorName {
			return fmt.Errorf("incorrect connector_name, expected %s, got: %s", connectorName, bnnService.CreateServiceSpec.Spec.Backend.ConnectorName)
		}
		return nil
	}
}

// Uses the API to check that the service was destroyed
func testAccCheckService_destroy(t *testing.T, id *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		r, _ := testAccClient.AccessTier.Get(*id)
		assert.Equal(t, r.ID, "")
		return nil
	}
}
