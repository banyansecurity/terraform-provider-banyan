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
	}

	d := schema.TestResourceDataRaw(t, resourceServiceInfraCommonSchema, svc_rdp_conn)
	svc_obj := expandRDPCreateService(d)

	json_spec, _ := ioutil.ReadFile("./specs/rdp-conn.json")
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
		"backend_http_connect":           true,
		"client_banyanproxy_listen_port": 9108,
	}

	d := schema.TestResourceDataRaw(t, resourceServiceInfraCommonSchema, svc_rdp_collection)
	svc_obj := expandRDPCreateService(d)

	json_spec, _ := ioutil.ReadFile("./specs/rdp-collection.json")
	var ref_obj service.CreateService
	_ = json.Unmarshal([]byte(json_spec), &ref_obj)

	AssertCreateServiceEqual(t, svc_obj, ref_obj)
}

func TestAccService_rdp(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckService_destroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			{
				Config: testAccService_rdp_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service_infra_rdp.acctest-rdp", &bnnService),
					testAccCheckAgainstJson(t, testAccService_rdp_create_json(rName), &bnnService.ServiceID),
				),
			},
		},
	})
}

// Returns terraform configuration for a typical rdp service
func testAccService_rdp_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service_infra_rdp" "acctest-rdp" {
  name        = "%s-rdp"
  description = "some RDP service description"
  cluster      = "us-west"
  access_tier   = "us-west1"
  domain      = "%s-rdp.corp.com"
  backend_domain = "%s-rdp.internal"
  backend_port = 3389
}
`, name, name, name)
}

func testAccService_rdp_create_json(name string) string {
	return fmt.Sprintf(`
{
    "kind": "BanyanService",
    "apiVersion": "rbac.banyanops.com/v1",
    "type": "origin",
    "metadata": {
        "name": "%s-rdp",
        "description": "some RDP service description",
        "cluster": "us-west",
        "tags": {
            "template": "TCP_USER",
            "user_facing": "true",
            "protocol": "tcp",
            "domain": "%s-rdp.corp.com",
            "port": "8443",
            "icon": "",
            "service_app_type": "RDP",
            "banyanproxy_mode": "TCP",
            "app_listen_port": "3389",
            "allow_user_override": false,
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
        "client_cidrs": []
    }
}
`, name, name, name, name, name)
}
