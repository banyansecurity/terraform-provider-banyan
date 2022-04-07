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
					testAccCheckExistingService("banyan_service_infra_tcp.acctest-tcp", &bnnService),
					testAccCheckAgainstJson(t, testAccService_tcp_create_json(rName), &bnnService),
				),
			},
		},
	})
}

// Returns terraform configuration for a typical k8s service
func testAccService_tcp_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service_infra_tcp" "acctest-tcp" {
  name        = "%s"
  description = "some database service description"
  cluster      = "us-west"
  access_tiers   = ["us-west1"]
  user_facing = true
  domain      = "%s.corp.com"
  backend_domain = "%s.internal"
  backend_port = 3389
}
`, name, name, name)
}

func testAccService_tcp_create_json(name string) string {
	return fmt.Sprintf(`
{
    "kind": "BanyanService",
    "apiVersion": "rbac.banyanops.com/v1",
    "type": "origin",
    "metadata": {
        "name": "%s",
        "description": "%s",
        "cluster": "us-west",
        "tags": {
            "%s": "TCP_USER",
            "user_facing": "true",
            "protocol": "tcp",
            "domain": "%s.corp.com",
            "port": "8443",
            "icon": "",
            "service_app_type": "RDP",
            "banyanproxy_mode": "TCP",
            "app_listen_port": "3389",
            "allow_user_override": true,
            "description_link": ""
        }
    },
    "spec": {
        "attributes": {
            "tls_sni": [
                "%s.corp.com"
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
                "name": "%s.internal",
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
                "%s.corp.com"
            ],
            "custom_tls_cert": {
                "enabled": false,
                "cert_file": "",
                "key_file": ""
            },
            "letsencrypt": false
        },
        "client_cidrs": []
    }
}

`, name, name, name, name, name, name, name)
}
