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
					testAccCheckExistingService("banyan_service_infra_db.acctest-database", &bnnService),
					testAccCheckAgainstJson(t, testAccService_database_create_json(rName), &bnnService.ServiceID),
				),
			},
		},
	})
}

// Returns terraform configuration for a typical database service
func testAccService_database_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service_infra_db" "acctest-database" {
  name        = "%s-db"
  description = "some database service description"
  cluster      = "us-west"
  access_tiers   = ["us-west1"]
  user_facing = true
  domain      = "%s-db.corp.com"
  backend_domain = ""
  backend_port = 0
  backend_http_connect = true
}
`, name, name)
}

func testAccService_database_create_json(name string) string {
	return fmt.Sprintf(`
{
    "kind": "BanyanService",
    "apiVersion": "rbac.banyanops.com/v1",
    "type": "origin",
    "metadata": {
        "name": "%s-db",
        "description": "some database service description",
        "cluster": "us-west",
        "tags": {
            "template": "TCP_USER",
            "user_facing": "true",
            "protocol": "tcp",
            "domain": "%s-db.corp.com",
            "port": "8443",
            "icon": "",
            "service_app_type": "DATABASE",
            "banyanproxy_mode": "CHAIN",
            "app_listen_port": "0",
            "allow_user_override": false,
            "description_link": ""
        }
    },
    "spec": {
        "attributes": {
            "tls_sni": [
                "%s-db.corp.com"
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
                "name": "",
                "port": "0",
                "tls": false,
                "tls_insecure": false,
                "client_certificate": false
            },
            "dns_overrides": {},
            "whitelist": [],
            "http_connect": true,
            "connector_name": ""
        },
        "cert_settings": {
            "dns_names": [
                "%s-db.corp.com"
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

`, name, name, name, name)
}
