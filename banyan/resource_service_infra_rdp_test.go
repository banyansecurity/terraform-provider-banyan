package banyan

import (
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"testing"
)

func TestAccService_rdp(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckService_destroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			{
				Config: testAccService_rdp_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service_infra_rdp.acctest-rdp", &bnnService),
				),
			},
		},
	})
}

// Returns terraform configuration for a typical rdp service
func testAccService_rdp_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service_infra_rdp" "acctest-rdp" {
  name        = "%s"
  description = "some RDP service description"
  cluster      = "us-west"
  access_tiers   = ["us-west1"]
  user_facing = true
  domain      = "%s.corp.com"
  backend {
	  domain = "%s.internal"
  }
}
`, name, name, name)
}
