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

func TestSchemaServiceInfraTcp_tcp_at(t *testing.T) {
	svc_tcp_at := map[string]interface{}{
		"name":                           "tcp-at",
		"description":                    "pybanyan tcp-at",
		"cluster":                        "cluster1",
		"access_tier":                    "gcp-wg",
		"domain":                         "test-tcp-at.bar.com",
		"allow_user_override":            true,
		"backend_domain":                 "10.10.1.6",
		"backend_port":                   6006,
		"client_banyanproxy_listen_port": 9119,
	}
	d := schema.TestResourceDataRaw(t, TcpSchema(), svc_tcp_at)
	svc_obj := TcpFromState(d)

	json_spec, _ := ioutil.ReadFile("./specs/service_infra/tcp-at.json")
	var ref_obj service.CreateService
	_ = json.Unmarshal(json_spec, &ref_obj)

	AssertCreateServiceEqual(t, svc_obj, ref_obj)
}

func TestSchemaServiceInfraTcp_tcp_conn(t *testing.T) {
	svc_tcp_conn := map[string]interface{}{
		"name":                           "tcp-conn",
		"description":                    "pybanyan tcp-conn",
		"cluster":                        "managed-cl-edge1",
		"connector":                      "test-connector",
		"domain":                         "test-tcp-conn.tdupnsan.getbnn.com",
		"backend_domain":                 "10.10.1.100",
		"backend_port":                   5000,
		"client_banyanproxy_listen_port": 9118,
		"allow_user_override":            true,
	}
	d := schema.TestResourceDataRaw(t, TcpSchema(), svc_tcp_conn)
	svc_obj := TcpFromState(d)

	json_spec, _ := ioutil.ReadFile("./specs/service_infra/tcp-conn.json")
	var ref_obj service.CreateService
	_ = json.Unmarshal(json_spec, &ref_obj)

	AssertCreateServiceEqual(t, svc_obj, ref_obj)
}

func TestAccService_tcp_depr(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckService_destroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			{
				Config: testAccService_tcp_depr_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service_infra_tcp.example", &bnnService),
				),
			},
		},
	})
}

func TestAccService_tcp(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckService_destroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			{
				Config: testAccService_tcp_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service_infra_tcp.example", &bnnService),
					testAccCheckServiceAgainstJson(t, testAccService_tcp_create_json(rName), &bnnService.ServiceID),
				),
			},
		},
	})
}

// Returns terraform configuration for a typical k8s service
func testAccService_tcp_depr_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service_infra_tcp" "example" {
  name        = "%s-tcp"
  description = "some tcp service description"
  access_tier   = "us-west1"
  domain      = "%s-tcp.corp.com"
  backend_domain = "%s-tcp.internal"
  backend_port = 5673
  client_banyanproxy_listen_port = 5673
}
`, name, name, name)
}

func testAccService_tcp_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service_infra_tcp" "example" {
  name        = "%s-tcp"
  description = "some tcp service description"
  access_tier   = "us-west1"
  domain      = "%s-tcp.corp.com"
  backend_domain = "%s-tcp.internal"
  backend_port = 5673
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
        "name": "%s-tcp",
        "description": "some tcp service description",
        "cluster": "cluster1",
        "tags": {
            "template": "TCP_USER",
            "user_facing": "true",
            "protocol": "tcp",
            "domain": "%s-tcp.corp.com",
            "port": "8443",
            "icon": "",
            "service_app_type": "GENERIC",
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
                "%s-tcp.corp.com"
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
                "name": "%s-tcp.internal",
                "port": "5673",
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
                "%s-tcp.corp.com"
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
