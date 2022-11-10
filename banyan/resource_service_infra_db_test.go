package banyan

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestSchemaServiceInfraDb_database_at(t *testing.T) {
	conn := map[string]interface{}{
		"name":                           "database-conn",
		"description":                    "pybanyan database-conn",
		"cluster":                        "managed-cl-edge1",
		"connector":                      "test-connector",
		"domain":                         "test-database-conn.tdupnsan.getbnn.com",
		"backend_domain":                 "10.10.1.123",
		"backend_port":                   3306,
		"client_banyanproxy_listen_port": 9299,
	}

	d := schema.TestResourceDataRaw(t, DbSchema(), conn)
	svc := DbFromState(d)
	j, _ := ioutil.ReadFile("./specs/database-conn.json")
	var ref_obj service.CreateService
	_ = json.Unmarshal(j, &ref_obj)
	AssertCreateServiceEqual(t, svc, ref_obj)
}

func TestAccService_database(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckService_destroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			{
				Config: testAccService_database_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service_db.example", &bnnService),
					testAccCheckAgainstJson(t, testAccService_database_create_json(rName), &bnnService.ServiceID),
				),
			},
		},
	})
}

// Returns terraform configuration for a typical database service
func testAccService_database_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service_db" "example" {
  name        = "%s"
  description = "some database service description"
  access_tier   = "us-west1"
  domain      = "%s.us-west.mycompany.com"
  backend_domain = "example-db.internal"
  backend_port = 3306
  policy = banyan_policy_infra.example.id
}

resource "banyan_policy_infra" "example" {
  name        = "%s-pol"
  description = "some infrastructure policy description"
  access {
    roles       = ["ANY"]
    trust_level = "High"
  }
}
`, name, name, name)
}

func testAccService_database_create_json(name string) string {
	return fmt.Sprintf(`
{
    "kind": "BanyanService",
    "apiVersion": "rbac.banyanops.com/v1",
    "type": "origin",
    "metadata": {
        "name": "%s",
        "description": "some database service description",
        "cluster": "cluster1",
        "tags": {
            "template": "TCP_USER",
            "user_facing": "true",
            "protocol": "tcp",
            "domain": "%s.us-west.mycompany.com",
            "port": "8443",
            "icon": "",
            "service_app_type": "DATABASE",
            "banyanproxy_mode": "TCP",
            "app_listen_port": "0",
            "allow_user_override": true,
            "description_link": "",
            "include_domains": []
        }
    },
    "spec": {
        "attributes": {
            "tls_sni": [
                "%s.us-west.mycompany.com"
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
                "name": "example-db.internal",
                "port": "3306",
                "tls": false,
                "tls_insecure": false,
                "client_certificate": false
            },
            "dns_overrides": {},
            "whitelist": [], 
            "http_connect": false,
            "connector_name": ""
        },
        "cert_settings": {
            "dns_names": [
                "%s.us-west.mycompany.com"
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

`, name, name, name, name)
}
