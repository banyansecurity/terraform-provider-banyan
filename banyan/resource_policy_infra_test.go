package banyan

import (
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/policy"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"testing"
)

func TestAccPolicy_infrastructure(t *testing.T) {
	var bnnPolicy policy.GetPolicy

	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckPolicy_destroy(t, &bnnPolicy.ID),
		Steps: []resource.TestStep{
			// Create the policy using terraform config and check that it exists
			{
				Config: fmt.Sprintf(`
					resource "banyan_policy_infra" "example" {
							name        = "%s"
							description = "some infrastructure policy description"
							access {
								roles       = ["ANY"]
								trust_level = "High"
							}
						}
					`, rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingPolicy("banyan_policy_infra.example", &bnnPolicy),
					testAccCheckPolicyAgainstJson(t, testAccPolicy_infrastructure_create_json(rName), &bnnPolicy.ID),
				),
			},
		},
	})
}

// Returns terraform configuration for the policy
func testAccPolicy_infrastructure_create_json(name string) string {
	return fmt.Sprintf(`
{
    "kind": "BanyanPolicy",
    "apiVersion": "rbac.banyanops.com/v1",
    "metadata": {
        "name": "%s",
        "description": "some infrastructure policy description",
        "tags": {
            "template": "USER"
        }
    },
    "type": "USER",
    "spec": {
        "access": [
            {
                "roles": [
                    "ANY"
                ],
                "rules": {
                    "l7_access": [],
                    "conditions": {
                        "trust_level": "High"
                    }
                }
            }
        ],
        "exception": {
            "src_addr": []
        },
        "options": {
            "disable_tls_client_authentication": false,
            "l7_protocol": ""
        }
    }
}
`, name)
}
