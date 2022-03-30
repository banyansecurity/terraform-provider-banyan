package banyan

import (
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"testing"
)

func TestAccService_tcp(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckService_destroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			{
				Config: testAccService_tcp_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_tcp_service.acctest-tcp", &bnnService),
				),
			},
		},
	})
}

// Returns terraform configuration for a typical k8s service
func testAccService_tcp_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_tcp_service" "acctest-tcp" {
  name        = "%s"
  description = "some tcp service description"
  cluster     = "us-west"
  access_tiers   = ["us-west1"]
  domain =  "%s.corp.com"
  frontend {
    port = 1234
  }
  backend {
    target {
      name = "%s.internal"
      port = 4321
    }
  }
}
`, name, name, name)
}
