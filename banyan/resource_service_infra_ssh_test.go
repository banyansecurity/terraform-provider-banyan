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
  description = "some ssh service"
  cluster     = "us-west"
  access_tiers   = ["us-west1", "us-east1"]
  domain      = "%s.corp.com"
  user_facing = true
  ssh_service_type   = "TRUSTCERT"
  write_ssh_config   = true
  ssh_chain_mode     = false
  ssh_host_directive = "%s.corp.com"
  frontend {
    port = 1234
  }
  backend {
    target {
      name               = "%s.internal"
      port               = 22
    }
  }
}
`, name, name, name, name)
}
