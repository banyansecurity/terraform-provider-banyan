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
					testAccCheckExistingService("banyan_service_web.acctest-web", &bnnService),
				),
			},
		},
	})
}

func TestAccService_complex_web(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckService_destroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			// Create the service using terraform config and check that it exists
			{
				Config: testAccService_complex_web_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service_web.acctest-web", &bnnService),
				),
			},
		},
	})
}

// Returns terraform configuration for a typical basic service
func testAccService_basic_web_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service_web" "acctest-web" {
  name        = "%s"
  description = "some web service description"
  cluster     = "us-west"
  access_tiers   = ["us-west1"]
  protocol = "https"
  domain = "%s.corp.com"
  port = 443
  backend {
      domain = "%s.internal"
      port = 8443
  }
}
`, name, name, name)
}

// Returns terraform configuration for a typical basic service
func testAccService_complex_web_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service_web" "acctest-web" {
  name             = "%s"
  description      = "some web service description"
  cluster          = "us-west"
  access_tiers     = ["us-west1"]
  protocol         = "https"
  domain           = "%s.corp.com"
  port             = 443
  description_link = "%s.corp.com"
  backend {
    domain             = "%s.internal"
    port               = 8443
    tls                = true
    tls_insecure       = true
    client_certificate = true
  }
  http_settings {
    enabled = true
    oidc_settings {
      enabled = true
      service_domain_name = %q
      post_auth_redirect_path = "/some/path"
      api_path = "/api"
      suppress_device_trust_verification = false
      trust_callbacks = {
        "somecallback" : "ohhey"
      }
    }
  }
}
`, name, name, name, name, name)
}
