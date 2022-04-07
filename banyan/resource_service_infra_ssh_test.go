package banyan

import (
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"testing"
)

func TestAccService_ssh(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckService_destroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			{
				Config: testAccService_ssh_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service_infra_ssh.acctest-ssh", &bnnService),
				),
			},
		},
	})
}

// Returns terraform configuration for a typical ssh service
func testAccService_ssh_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service_infra_ssh" "acctest-ssh" {
  name        = "%s"
  description = "some SSH service description"
  cluster      = "us-west"
  access_tiers   = ["us-west1"]
  user_facing = true
  ssh_host_directive = "%s.corp.com"
  domain      = "%s.corp.com"
  backend {
	  domain = "%s.internal"
  }
}
`, name, name, name, name)
}
