package banyan

import (
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"testing"
)

func TestAccService_k8s(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckService_destroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			{
				Config: testAccService_k8s_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_k8s_service.acctest-k8s", &bnnService),
				),
			},
		},
	})
}

// Returns terraform configuration for a typical k8s service
func testAccService_k8s_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_k8s_service" "acctest-k8s" {
  name        = "%s"
  description = "some k8s service description"
  cluster     = "us-west"
  access_tiers   = ["us-west1"]
  user_facing = true
  kube_cluster_name = "k8s-cluster"
  kube_ca_key = "k8scAk3yH3re"
  domain      = "%s.corp.com"
  tls_sni     = ["%s-alternate-name.corp.com"]
  frontend {
    port = 8443
  }
  backend {
    target {
      name = "%s.internal"
      port = 3389
    }
  }
  cert_settings {
    dns_names = ["%s-alternate-name.corp.com"]
  }
}
`, name, name, name, name, name)
}
