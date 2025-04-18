package banyan

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestSchemaServiceInfraRdp_rdp_conn(t *testing.T) {
	svc_rdp_conn := map[string]interface{}{
		"name":                           "rdp-conn",
		"description":                    "pybanyan rdp-conn",
		"cluster":                        "managed-cl-edge1",
		"connector":                      "test-connector",
		"domain":                         "test-rdp-conn.tdupnsan.getbnn.com",
		"backend_domain":                 "10.10.2.1",
		"backend_port":                   3309,
		"client_banyanproxy_listen_port": 9109,
		"rdp_settings":                   []interface{}{"devicestoredirect:s:*"},
	}

	d := schema.TestResourceDataRaw(t, RdpSchema(), svc_rdp_conn)
	svc_obj := RdpFromState(d)

	json_spec, _ := os.ReadFile("./specs/service_infra/rdp-conn.json")
	var ref_obj service.CreateService
	_ = json.Unmarshal([]byte(json_spec), &ref_obj)

	AssertCreateServiceEqual(t, svc_obj, ref_obj)
}

func TestSchemaServiceInfraRdp_rdp_collection(t *testing.T) {
	svc_rdp_collection := map[string]interface{}{
		"name":                           "rdp-collection",
		"description":                    "pybanyan rdp-collection",
		"cluster":                        "managed-cl-edge1",
		"connector":                      "test-connector",
		"domain":                         "test-rdp-collection.tdupnsan.getbnn.com",
		"http_connect":                   true,
		"client_banyanproxy_listen_port": 9108,
		"rdp_settings":                   []interface{}{"devicestoredirect:s:*"},
	}

	d := schema.TestResourceDataRaw(t, RdpSchema(), svc_rdp_collection)
	svc_obj := RdpFromState(d)

	json_spec, _ := os.ReadFile("./specs/service_infra/rdp-collection.json")
	var ref_obj service.CreateService
	_ = json.Unmarshal([]byte(json_spec), &ref_obj)

	AssertCreateServiceEqual(t, svc_obj, ref_obj)
}

func TestAccService_infra_rdp(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckServiceDestroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			{
				Config: testAccService_infra_rdp_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service_rdp.example", &bnnService),
					testAccCheckServiceAgainstJson(t, testAccService_infra_rdp_create_json(rName), &bnnService.ServiceID),
				),
			},
			{
				ResourceName:      "banyan_service_rdp.example",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccService_infra_rdp_without_rdp_settings(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckServiceDestroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			{
				Config: testAccService_infra_rdp_create_without_rdp_settings(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service_rdp.example_without_rdp", &bnnService),
					testAccCheckServiceAgainstJson(t, testAccService_infra_rdp_create_without_rdp_settings_json(rName), &bnnService.ServiceID),
				),
			},
			{
				ResourceName:      "banyan_service_rdp.example_without_rdp",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// Returns terraform configuration for a typical rdp service
func testAccService_infra_rdp_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service_rdp" "example" {
  name           = "%s-rdp"
  description    = "some RDP service description"
  access_tier    = "us-west1"
  domain         = "%s-rdp.corp.com"
  backend_domain = "%s-rdp.internal"
  backend_port   = 3389
  rdp_settings   = ["devicestoredirect:s:*"]
  policy_enforcing = false
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
        "cluster": "cluster1",
        "tags": {
            "template": "TCP_USER",
            "user_facing": "true",
            "protocol": "tcp",
            "domain": "%s-rdp.corp.com",
            "port": "8443",
            "icon": "",
            "service_app_type": "RDP",
            "banyanproxy_mode": "TCP",
            "app_listen_port": "",
            "allow_user_override": true,
            "description_link": "",
            "rdp_settings": ["devicestoredirect:s:*"]
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

func testAccService_infra_rdp_create_without_rdp_settings(name string) string {
	return fmt.Sprintf(`
resource "banyan_service_rdp" "example_without_rdp" {
  name           = "%s-rdp"
  description    = "some RDP service description"
  access_tier    = "us-west1"
  domain         = "%s-rdp.corp.com"
  backend_domain = "%s-rdp.internal"
  backend_port   = 3389
  policy_enforcing = false
}
`, name, name, name)
}

func testAccService_infra_rdp_create_without_rdp_settings_json(name string) string {
	return fmt.Sprintf(`
{
    "kind": "BanyanService",
    "apiVersion": "rbac.banyanops.com/v1",
    "type": "origin",
    "metadata": {
        "name": "%s-rdp",
        "description": "some RDP service description",
        "cluster": "cluster1",
        "tags": {
            "template": "TCP_USER",
            "user_facing": "true",
            "protocol": "tcp",
            "domain": "%s-rdp.corp.com",
            "port": "8443",
            "icon": "",
            "service_app_type": "RDP",
            "banyanproxy_mode": "TCP",
            "app_listen_port": "",
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

func TestAccRDPService_basic(t *testing.T) {

	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: nil,
		Steps: []resource.TestStep{
			//test case with policy enforce
			{
				Config: fmt.Sprintf(`
					resource "banyan_api_key" "example" {
						name              = "%s"
						description       = "realdescription"
						scope             = "access_tier"
					}

					resource banyan_accesstier "example" {
						name = "%s"
						address = "*.example.com"
						api_key_id = banyan_api_key.example.id
					}

					resource "banyan_policy_infra" "example" {
						name        = "%s"
						description = "some tunnel policy description"
						access {
							roles       = ["ANY"]
							trust_level = "High"
						}
					}

					resource "banyan_service_rdp" "example" {
						name              = "%s"
						description       = "realdescription"
						access_tier 	  = banyan_accesstier.example.name
						domain            = "test-k8s.corp.com"
						policy            = banyan_policy_infra.example.id
                        backend_domain    = "10.1.34.54"
                        backend_port      = 3389
					}
					`, rName, rName, rName, rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("banyan_service_rdp.example", "name", rName),
				),
			},
			{
				ResourceName:      "banyan_service_rdp.example",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// test case without policy enforcing
			{
				Config: fmt.Sprintf(`
					resource "banyan_api_key" "example" {
						name              = "%s"
						description       = "realdescription"
						scope             = "access_tier"
					}

					resource banyan_accesstier "example" {
						name = "%s"
						address = "*.example.com"
						api_key_id = banyan_api_key.example.id
					}

					resource "banyan_policy_infra" "example" {
						name        = "%s"
						description = "some tunnel policy description"
						access {
							roles       = ["ANY"]
							trust_level = "High"
						}
					}

					resource "banyan_service_rdp" "example" {
						name              = "%s"
						description       = "realdescription"
						access_tier 	  = banyan_accesstier.example.name
						domain            = "test-k8s.corp.com"
						policy            = banyan_policy_infra.example.id
                        backend_domain    = "10.1.34.54"
                        backend_port      = 3389
					}
					`, rName, rName, rName, rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("banyan_service_rdp.example", "name", rName),
				),
			},
			{
				ResourceName:      "banyan_service_rdp.example",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}
