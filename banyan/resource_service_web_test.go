package banyan

import (
	"fmt"
	"testing"

	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
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
					testAccCheckAgainstJson(t, testAccService_basic_web_create_json(rName), &bnnService.ServiceID),
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
  name        = "%s-web"
  description = "some web service description"
  cluster     = "us-west"
  access_tier   = "us-west1"
  domain = "%s-web.corp.com"
  port = 443
  backend_domain = "%s-web.internal"
  backend_port = 8443
}
`, name, name, name)
}

func testAccService_basic_web_create_json(name string) string {
	return fmt.Sprintf(`
{
    "kind": "BanyanService",
    "apiVersion": "rbac.banyanops.com/v1",
    "type": "origin",
    "metadata": {
        "name": "%s-web",
        "description": "some web service description",
        "cluster": "us-west",
        "tags": {
            "template": "WEB_USER",
            "user_facing": "true",
            "protocol": "https",
            "domain": "%s-web.corp.com",
            "port": "443",
            "icon": "",
            "service_app_type": "WEB",
            "description_link": ""
        }
    },
    "spec": {
        "attributes": {
            "tls_sni": [
                "%s-web.corp.com"
            ],
            "frontend_addresses": [
                {
                    "cidr": "",
                    "port": "443"
                }
            ],
            "host_tag_selector": [
                {
                    "com.banyanops.hosttag.site_name": "us-west1"
                }
            ],
            "disable_private_dns": false
        },
        "backend": {
            "target": {
                "name": "%s-web.internal",
                "port": "8443",
                "tls": false,
                "tls_insecure": false,
                "client_certificate": false
            },
            "dns_overrides": {},
            "whitelist": [],
            "connector_name": ""
        },
        "cert_settings": {
            "dns_names": [
                "%s-web.corp.com"
            ],
            "custom_tls_cert": {
                "enabled": false,
                "cert_file": "",
                "key_file": ""
            },
            "letsencrypt": false
        },
        "http_settings": {
            "enabled": true,
            "oidc_settings": {
                "enabled": true,
                "service_domain_name": "https://%s-web.corp.com",
                "post_auth_redirect_path": "",
                "api_path": "",
                "trust_callbacks": null,
                "suppress_device_trust_verification": false
            },
            "http_health_check": {
                "enabled": false,
                "addresses": null,
                "method": "",
                "path": "",
                "user_agent": "",
                "from_address": [],
                "https": false
            },
            "http_redirect": {
                "enabled": false,
                "addresses": null,
                "from_address": null,
                "url": "",
                "status_code": 0
            },
            "exempted_paths": {
                "enabled": false
            },
            "headers": {}
        },
        "client_cidrs": []
    }
}
`, name, name, name, name, name, name)
}

// Returns terraform configuration for a typical basic service
func testAccService_complex_web_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service_web" "acctest-web" {
  name             = "%s"
  description      = "some web service description"
  cluster          = "us-west"
  connector        = "foobar"
  domain           = "%s.corp.com"
  port             = 443
  backend_domain   = "%s.internal"
  backend_port     = 4321
  backend_tls      = true
  backend_tls_insecure = true
}
`, name, name, name)
}
