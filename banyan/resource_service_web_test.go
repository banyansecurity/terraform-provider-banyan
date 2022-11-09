package banyan

import (
	"fmt"
	"testing"

	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// Creates and updates a web service with required parameters
func TestAccService_required_web(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckService_destroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			// Create the service using terraform config and check that it exists
			{
				Config: fmt.Sprintf(`
					resource "banyan_policy_web" "example" {
						name        = "%s-pol"
						description = "some web policy description"
						access {
							roles       = ["ANY"]
							trust_level = "High"
						}
					}
					resource "banyan_service_web" "example" {
						name        = "%s-web"
						access_tier   = "us-west1"
						domain = "%s-web.corp.com"
						backend_domain = "%s-web.internal"
						backend_port = 8443
						policy = banyan_policy_web.example.id
					}
					`, rName, rName, rName, rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service_web.example", &bnnService),
					testAccCheckAgainstJson(t, testAccService_basic_web_create_json(rName), &bnnService.ServiceID),
				),
			},
			{
				Config: fmt.Sprintf(`
					resource "banyan_policy_web" "example" {
						name        = "%s-pol"
						description = "some web policy description"
						access {
							roles       = ["ANY"]
							trust_level = "High"
						}
					}
					resource "banyan_service_web" "example" {
						name        = "%s-web"
						access_tier   = "us-west1"
						domain = "%s-web-updated.corp.com"
						backend_domain = "%s-web-updated.internal"
						backend_port = 8444
						policy = banyan_policy_web.example.id
					}
					`, rName, rName, rName, rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service_web.example", &bnnService),
					testAccCheckAgainstJson(t, testAccService_basic_web_update_json(rName), &bnnService.ServiceID),
				),
			},
		},
	})
}

// Creates and updates a web service with optional parameters
func TestAccService_optional_web(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckService_destroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
					resource "banyan_service_web" "example" {
						name             = "%s"
						description      = "some web service description"
						connector        = "foobar"
						domain           = "%s.corp.com"
						port             = 443
						backend_domain   = "%s.internal"
						backend_port     = 4321
						backend_tls      = true
						backend_tls_insecure = true
					}
					`, rName, rName, rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service_web.example", &bnnService),
				),
			},
			{
				Config: fmt.Sprintf(`
					resource "banyan_service_web" "example" {
						name             = "%s"
						description      = "some web service description"
						connector        = "foobar"
						domain           = "%s.corp.com"
						port             = 444
						backend_domain   = "%s.internal"
						backend_port     = 4322
						backend_tls      = false
					}
					`, rName, rName, rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service_web.example", &bnnService),
				),
			},
		},
	})
}

func testAccService_basic_web_create_json(name string) string {
	return fmt.Sprintf(`
{
    "kind": "BanyanService",
    "apiVersion": "rbac.banyanops.com/v1",
    "type": "origin",
    "metadata": {
        "name": "%s-web",
        "description": "",
        "cluster": "tortoise",
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

func testAccService_basic_web_update_json(name string) string {
	return fmt.Sprintf(`
{
    "kind": "BanyanService",
    "apiVersion": "rbac.banyanops.com/v1",
    "type": "origin",
    "metadata": {
        "name": "%s-web",
        "description": "",
        "cluster": "tortoise",
        "tags": {
            "template": "WEB_USER",
            "user_facing": "true",
            "protocol": "https",
            "domain": "%s-web-updated.corp.com",
            "port": "443",
            "icon": "",
            "service_app_type": "WEB",
            "description_link": ""
        }
    },
    "spec": {
        "attributes": {
            "tls_sni": [
                "%s-web-updated.corp.com"
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
                "name": "%s-web-updated.internal",
                "port": "8444",
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
                "%s-web-updated.corp.com"
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
                "service_domain_name": "https://%s-web-updated.corp.com",
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
