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

func TestSchemaServiceInfraSsh_ssh_at(t *testing.T) {
	svc_ssh_at := map[string]interface{}{
		"name":                      "ssh-at",
		"description":               "pybanyan ssh-at",
		"cluster":                   "cluster1",
		"access_tier":               "gcp-wg",
		"domain":                    "test-ssh-at.bar.com",
		"http_connect":              true,
		"client_ssh_host_directive": "10.10.1.*",
	}
	d := schema.TestResourceDataRaw(t, SshSchema(), svc_ssh_at)
	svc_obj := SshFromState(d)

	json_spec, _ := os.ReadFile("./specs/service_infra/ssh-at.json")
	var ref_obj service.CreateService
	_ = json.Unmarshal([]byte(json_spec), &ref_obj)

	AssertCreateServiceEqual(t, svc_obj, ref_obj)
}

func TestSchemaServiceInfraSsh_ssh_conn(t *testing.T) {
	svc_ssh_conn := map[string]interface{}{
		"name":           "ssh-conn",
		"description":    "pybanyan ssh-conn",
		"cluster":        "managed-cl-edge1",
		"connector":      "test-connector",
		"domain":         "test-ssh-conn.tdupnsan.getbnn.com",
		"backend_domain": "10.10.1.1",
		"backend_port":   22,
	}
	d := schema.TestResourceDataRaw(t, SshSchema(), svc_ssh_conn)
	svc_obj := SshFromState(d)

	json_spec, _ := os.ReadFile("./specs/service_infra/ssh-conn.json")
	var ref_obj service.CreateService
	_ = json.Unmarshal([]byte(json_spec), &ref_obj)

	AssertCreateServiceEqual(t, svc_obj, ref_obj)
}

func TestAccService_ssh(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckServiceDestroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			{
				Config: testAccService_ssh_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service_ssh.example", &bnnService),
					testAccCheckServiceAgainstJson(t, testAccService_ssh_create_json(rName), &bnnService.ServiceID),
				),
			},
			{
				ResourceName:      "banyan_service_ssh.example",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// Returns terraform configuration for a typical ssh service
func testAccService_ssh_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service_ssh" "example" {
  name                      = "%s-ssh"
  description               = "some SSH service description"
  access_tier               = "us-west1"
  domain                    = "%s-ssh.corp.com"
  backend_domain            = "%s-ssh.internal"
  backend_port              = 22
  policy_enforcing          = false
}
`, name, name, name)
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
        "cluster": "cluster1",
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
            "ssh_host_directive": "",
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

func TestAccSSHService_basic(t *testing.T) {

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

					resource "banyan_service_ssh" "example" {
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
					resource.TestCheckResourceAttr("banyan_service_ssh.example", "name", rName),
				),
			},
			{
				ResourceName:      "banyan_service_ssh.example",
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

					resource "banyan_service_ssh" "example" {
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
					resource.TestCheckResourceAttr("banyan_service_ssh.example", "name", rName),
				),
			},
			{
				ResourceName:      "banyan_service_ssh.example",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}
