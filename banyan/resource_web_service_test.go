package banyan

import (
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"testing"
)

// Use the terraform plugin sdk testing framework for acceptance testing banyan service lifecycle
func TestAccService_basic_web(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckService_destroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			// Create the service using terraform config and check that it exists
			{
				Config: testAccService_basic_web_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_web_service.acctest-web", &bnnService),
				),
			},
		},
	})
}

// Returns terraform configuration for a typical basic service
func testAccService_basic_web_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_web_service" "acctest-web" {
  name        = "%s"
  description = "some web service description"
  cluster     = "us-west"
  access_tiers   = ["us-west1"]
  domain = "%s.corp.com"
  frontend {
    port = 443
  }
  backend {
    target {
      name = "%s.internal"
      port = 8443
    }
  }
}
`, name, name, name)
}
