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
	}
	d := schema.TestResourceDataRaw(t, K8sSchema(), svc_k8s_conn)
	svc_obj := K8sFromState(d)

	json_spec, _ := ioutil.ReadFile("./specs/k8s-conn.json")
	var ref_obj service.CreateService
	_ = json.Unmarshal(json_spec, &ref_obj)

	AssertCreateServiceEqual(t, svc_obj, ref_obj)
}

func TestAccService_k8s(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckService_destroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			{
				Config: testAccService_k8s_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service_infra_k8s.example", &bnnService),
				),
			},
		},
	})
}

// Returns terraform configuration for a typical k8s service
func testAccService_k8s_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service_infra_k8s" "example" {
  name        = "%s-k8s"
  description = "some k8s service description"
  cluster     = "us-west"
  access_tier = "us-west1"
  domain      = "%s-k8s.corp.com"
  backend_dns_override_for_domain = "%s-k8s.service"
  client_kube_cluster_name = "k8s-cluster"
  client_kube_ca_key = "k8scAk3yH3re"
  client_banyanproxy_listen_port = "9119"
}
`, name, name, name)
}
