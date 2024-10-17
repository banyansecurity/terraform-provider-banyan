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

func TestSchemaServiceInfraK8s_k8s_conn(t *testing.T) {
	svc_k8s_conn := map[string]interface{}{
		"name":                            "k8s-conn",
		"description":                     "pybanyan k8s-conn",
		"cluster":                         "managed-cl-edge1",
		"connector":                       "test-connector",
		"domain":                          "test-k8s-conn.tdupnsan.getbnn.com",
		"backend_dns_override_for_domain": "myoidcproxy.amazonaws.com",
		"client_banyanproxy_listen_port":  9199,
		"client_kube_cluster_name":        "eks-hero",
		"client_kube_ca_key":              "AAAA1234",
		"backend_port":                    0,
	}
	d := schema.TestResourceDataRaw(t, K8sSchema(), svc_k8s_conn)
	svc_obj := K8sFromState(d)

	json_spec, _ := os.ReadFile("./specs/service_infra/k8s-conn.json")
	var ref_obj service.CreateService
	_ = json.Unmarshal(json_spec, &ref_obj)

	AssertCreateServiceEqual(t, svc_obj, ref_obj)
}

func TestAccService_k8s(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckServiceDestroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
					resource "banyan_service_k8s" "example" {
					  name        = "%s-k8s"
					  description = "some k8s service description"
					  access_tier = "us-west1"
					  domain      = "%s-k8s.corp.com"
					  backend_dns_override_for_domain = "%s-k8s.service"
					  client_kube_cluster_name = "k8s-cluster"
					  client_kube_ca_key = "k8scAk3yH3re"
					  client_banyanproxy_listen_port = "9119"
					  policy_enforcing = false
					}
					`, rName, rName, rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service_k8s.example", &bnnService),
				),
			},
			{
				ResourceName:      "banyan_service_k8s.example",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccK8Service_basic(t *testing.T) {

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

					resource "banyan_service_k8s" "example" {
						name              = "%s"
						description       = "realdescription"
						access_tier 	  = banyan_accesstier.example.name
						domain            = "test-k8s.corp.com"
						policy            = banyan_policy_infra.example.id
						policy_enforcing  = false
						backend_dns_override_for_domain = "test-k8s.service"
						client_kube_cluster_name = "k8s-cluster"
						client_kube_ca_key = "k8scAk3yH3re"
						client_banyanproxy_listen_port = "9119"
					}
					`, rName, rName, rName, rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("banyan_service_k8s.example", "name", rName),
				),
			},
			{
				ResourceName:      "banyan_service_k8s.example",
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

					resource "banyan_service_k8s" "example" {
						name              = "%s"
						description       = "realdescription"
						access_tier 	  = banyan_accesstier.example.name
						domain            = "test-k8s.corp.com"
						policy            = banyan_policy_infra.example.id
						backend_dns_override_for_domain = "test-k8s.service"
						client_kube_cluster_name = "k8s-cluster"
						client_kube_ca_key = "k8scAk3yH3re"
						client_banyanproxy_listen_port = "9119"
					}
					`, rName, rName, rName, rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("banyan_service_k8s.example", "name", rName),
				),
			},
			{
				ResourceName:      "banyan_service_k8s.example",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}
