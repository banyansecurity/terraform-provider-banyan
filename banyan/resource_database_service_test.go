package banyan

import (
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"testing"
)

func TestAccService_database(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckService_destroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			{
				Config: testAccService_database_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_database_service.acctest-database", &bnnService),
				),
			},
		},
	})
}

// Returns terraform configuration for a typical database service
func testAccService_database_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_database_service" "acctest-database" {
  name        = "%s"
  description = "some database service description"
  cluster     = "us-west"
  access_tiers   = ["us-west1"]
  user_facing = true
  domain      = "%s.corp.com"
  tls_sni     = ["%s2.corp.com"]
  frontend {
    port = 845
  }
  backend {
    target {
      name = "%s.internal"
      port = 8845
    }
  }
  cert_settings {
    dns_names = ["%s2.corp.com"]
  }
}
`, name, name, name, name, name)
}
