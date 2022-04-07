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
					testAccCheckAgainstJson(t, testAccService_ssh_create_json(rName), &bnnService.ServiceID),
				),
			},
		},
	})
}

// Returns terraform configuration for a typical ssh service
func testAccService_ssh_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service_infra_ssh" "acctest-ssh" {
  name        = "%s-ssh"
  description = "some SSH service description"
  cluster      = "us-west"
  access_tier   = "us-west1"
  user_facing = true
  ssh_host_directive = "%s-ssh.corp.com"
  domain      = "%s-ssh.corp.com"
  backend_domain = "%s-ssh.internal"
  backend_port = 22
}
`, name, name, name, name)
}

func testAccService_ssh_create_json(name string) string {
	return fmt.Sprintf(`
{
    "kind": "BanyanService",
    "apiVersion": "rbac.banyanops.com/v1",
    "type": "origin",
    "metadata": {
        "name": "%s-ssh",
        "description": "some SSH service description",
        "cluster": "us-west",
        "tags": {
            "template": "TCP_USER",
            "user_facing": "true",
            "protocol": "tcp",
            "domain": "%s-ssh.corp.com",
            "port": "8443",
            "icon": "",
            "service_app_type": "SSH",
            "ssh_service_type": "TRUSTCERT",
            "write_ssh_config": true,
            "ssh_chain_mode": false,
            "ssh_host_directive": "%s-ssh.corp.com",
            "description_link": ""
        }
    },
    "spec": {
        "attributes": {
            "tls_sni": [
                "%s-ssh.corp.com"
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
                "name": "%s-ssh.internal",
                "port": "22",
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
                "%s-ssh.corp.com"
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
`, name, name, name, name, name, name)
}
