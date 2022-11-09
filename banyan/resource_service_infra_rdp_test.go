package banyan

import (
	"fmt"
	"testing"

	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccService_infra_rdp(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckService_destroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			{
				Config: testAccService_infra_rdp_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service_infra_rdp.example", &bnnService),
					testAccCheckAgainstJson(t, testAccService_infra_rdp_create_json(rName), &bnnService.ServiceID),
				),
			},
		},
	})
}

// Returns terraform configuration for a typical rdp service
func testAccService_infra_rdp_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service_infra_rdp" "example" {
  name           = "%s-rdp"
  description    = "some RDP service description"
  access_tier    = "us-west1"
  domain         = "%s-rdp.corp.com"
  backend_domain = "%s-rdp.internal"
  backend_port   = 3389
}
`, name, name, name)
}

func testAccService_infra_rdp_create_json(name string) string {
	return fmt.Sprintf(`
{
    "kind": "BanyanService",
    "apiVersion": "rbac.banyanops.com/v1",
    "type": "origin",
    "metadata": {
        "name": "%s-rdp",
        "description": "some RDP service description",
        "cluster": "tortoise",
        "tags": {
            "template": "TCP_USER",
            "user_facing": "true",
            "protocol": "tcp",
            "domain": "%s-rdp.corp.com",
            "port": "8443",
            "icon": "",
            "service_app_type": "RDP",
            "banyanproxy_mode": "TCP",
            "app_listen_port": "0",
            "allow_user_override": true,
            "description_link": ""
        }
    },
    "spec": {
        "attributes": {
            "tls_sni": [
                "%s-rdp.corp.com"
            ],
            "frontend_addresses": [
                {
                    "cidr": "",
                    "port": "8443"
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
                "name": "%s-rdp.internal",
                "port": "3389",
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
                "%s-rdp.corp.com"
            ],
            "custom_tls_cert": {
                "enabled": false,
                "cert_file": "",
                "key_file": ""
            },
            "letsencrypt": false
        },
        "http_settings": {
            "enabled": false,
            "oidc_settings": {
                "enabled": false,
                "service_domain_name": "",
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
                "enabled": false,
                "patterns": [
                    {
                        "hosts": [
                            {
                                "origin_header": [],
                                "target": []
                            }
                        ],
                        "methods": [],
                        "paths": [],
                        "mandatory_headers": []
                    }
                ]
            },
            "headers": {}
        },        
        "client_cidrs": []
    }
}
`, name, name, name, name, name)
}
