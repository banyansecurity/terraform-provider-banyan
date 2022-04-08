package banyan

import (
	"encoding/json"
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"io/ioutil"
	"testing"
)

func TestSchemaServiceInfraTcp_web_at(t *testing.T) {
	svcInfraTcpAT := map[string]interface{}{
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
	d := schema.TestResourceDataRaw(t, resourceServiceInfraTcpSchema, svcInfraTcpAT)

	svcObj := service.CreateService{
		Metadata: service.Metadata{
			Name:        d.Get("name").(string),
			Description: d.Get("description").(string),
			ClusterName: d.Get("cluster").(string),
			Tags:        expandTCPMetatdataTags(d),
		},
		Kind:       "BanyanService",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "origin",
		Spec:       expandInfraServiceSpec(d),
	}

	jsonSpec, _ := ioutil.ReadFile("./specs/tcp-at.json")
	var refObj service.CreateService
	_ = json.Unmarshal(jsonSpec, &refObj)

	AssertCreateServiceEqual(t, svcObj, refObj)
}

func TestSchemaServiceInfraTcp_web_conn(t *testing.T) {
	svcInfraTcpConn := map[string]interface{}{
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
	d := schema.TestResourceDataRaw(t, resourceServiceInfraTcpSchema, svcInfraTcpConn)

	svcObj := service.CreateService{
		Metadata: service.Metadata{
			Name:        d.Get("name").(string),
			Description: d.Get("description").(string),
			ClusterName: d.Get("cluster").(string),
			Tags:        expandTCPMetatdataTags(d),
		},
		Kind:       "BanyanService",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "origin",
		Spec:       expandInfraServiceSpec(d),
	}

	jsonSpec, _ := ioutil.ReadFile("./specs/tcp-conn.json")
	var refObj service.CreateService
	_ = json.Unmarshal(jsonSpec, &refObj)

	AssertCreateServiceEqual(t, svcObj, refObj)
}

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
					testAccCheckAgainstJson(t, testAccService_tcp_create_json(rName), &bnnService.ServiceID),
				),
			},
		},
	})
}

// Returns terraform configuration for a typical k8s service
func testAccService_tcp_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service_infra_tcp" "acctest-tcp" {
  name        = "%s-tcp"
  description = "some tcp service description"
  cluster      = "us-west"
  access_tier   = "us-west1"
  domain      = "%s-tcp.corp.com"
  backend_domain = "%s-tcp.internal"
  backend_port = 5673
  client_banyanproxy_listen_port = 5673
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
        "cluster": "us-west",
        "tags": {
            "template": "TCP_USER",
            "user_facing": "true",
            "protocol": "tcp",
            "domain": "%s-tcp.corp.com",
            "port": "8443",
            "icon": "",
            "service_app_type": "GENERIC",
            "banyanproxy_mode": "TCP",
            "app_listen_port": "5673",
            "allow_user_override": false,
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
                "enabled": false
            },
            "headers": {}
        },
        "client_cidrs": []
    }
}
`, name, name, name, name, name)
}
