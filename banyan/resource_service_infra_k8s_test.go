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
					testAccCheckExistingService("banyan_service_infra_k8s.acctest-k8s", &bnnService),
					testAccCheckAgainstJson(t, testAccService_k8s_create_json(rName), &bnnService.ServiceID),
				),
			},
		},
	})
}

// Returns terraform configuration for a typical k8s service
func testAccService_k8s_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service_infra_k8s" "acctest-k8s" {
  name        = "%s-k8s"
  description = "some k8s service description"
  cluster     = "us-west"
  access_tiers   = ["us-west1"]
  domain      = "%s-k8s.corp.com"
  user_facing   = true
  client_kube_cluster_name = "k8s-cluster"
  client_kube_ca_key = "k8scAk3yH3re"
  backend_dns_override_for_domain = "%s-k8s.service"
}
`, name, name, name)
}

func testAccService_k8s_create_json(name string) string {
	return fmt.Sprintf(`
{
    "kind": "BanyanService",
    "apiVersion": "rbac.banyanops.com/v1",
    "type": "origin",
    "metadata": {
        "name": "%s-k8s",
        "description": "some k8s service description",
        "cluster": "us-west",
        "tags": {
            "template": "TCP_USER",
            "user_facing": "true",
            "protocol": "tcp",
            "domain": "%s-k8s.corp.com",
            "port": "8443",
            "icon": "",
            "service_app_type": "K8S",
            "banyanproxy_mode": "CHAIN",
            "app_listen_port": "8443",
            "allow_user_override": false,
            "kube_cluster_name": "k8s-cluster",
            "kube_ca_key": "k8scAk3yH3re",
            "description_link": ""
        }
    },
    "spec": {
        "attributes": {
            "tls_sni": [
                "%s-k8s.corp.com"
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
                "port": "",
                "tls": false,
                "tls_insecure": false,
                "client_certificate": false
            },
            "dns_overrides": {
                "%s-k8s.corp.com": "%s-k8s.service"
            },
            "whitelist": [],
            "allow_patterns": [
                {
                    "hostnames": [
                        "%s-k8s.corp.com"
                    ]
                }
            ],
            "http_connect": true,
            "connector_name": ""
        },
        "cert_settings": {
            "dns_names": [
                "%s-k8s.corp.com"
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