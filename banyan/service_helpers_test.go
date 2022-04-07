package banyan

import (
	"encoding/json"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"testing"
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

func testAccCheckAgainstJson(t *testing.T, path string, id *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		got, _, err := testAccClient.Service.Get(*id)
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
