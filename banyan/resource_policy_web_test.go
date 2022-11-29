package banyan

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/banyansecurity/terraform-banyan-provider/client/policy"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/assert"
)

func TestSchemaPolicyWeb_l7(t *testing.T) {

	access1 := map[string]interface{}{
		"roles":       []interface{}{"Contractors", "ServiceAccounts"},
		"trust_level": "",
		"l7_access": []interface{}{
			map[string]interface{}{
				"resources": []interface{}{"!/wp-admin*", "!/wp-login*"},
				"actions":   []interface{}{"*"},
			},
			map[string]interface{}{
				"resources": []interface{}{"*"},
				"actions":   []interface{}{"*"},
			},
		},
	}

	access2 := map[string]interface{}{
		"roles":       []interface{}{"UsersRegisteredDevice"},
		"trust_level": "Low",
		"l7_access": []interface{}{
			map[string]interface{}{
				"resources": []interface{}{"!/wp-admin*"},
				"actions":   []interface{}{"*"},
			},
			map[string]interface{}{
				"resources": []interface{}{"*"},
				"actions":   []interface{}{"*"},
			},
		},
	}

	access3 := map[string]interface{}{
		"roles":       []interface{}{"AdminsCorpDevice"},
		"trust_level": "High",
	}

	policy_l7 := map[string]interface{}{
		"name":        "Wordpress w API Controls",
		"description": "[TF] Different levels of access based on user+device attributes & trust",
		"access":      []interface{}{access1, access2, access3},
	}
	d := schema.TestResourceDataRaw(t, PolicyWebSchema(), policy_l7)
	policy_obj := policyWebFromState(d)

	json_spec, _ := ioutil.ReadFile("./specs/policy/l7.json")
	var ref_obj policy.Object
	_ = json.Unmarshal([]byte(json_spec), &ref_obj)

	AssertPolicySpecEqual(t, policy_obj, ref_obj)
}

func TestAccPolicy_web_basic(t *testing.T) {
	var bnnPolicy policy.GetPolicy

	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckPolicy_destroy(t, &bnnPolicy.ID),
		Steps: []resource.TestStep{
			// Create the policy using terraform config and check that it exists
			{
				Config: fmt.Sprintf(`
					resource "banyan_policy_web" "example" {
						name        = %q
						description = "some web policy description"
						access {
							roles                             = ["ANY"]
							trust_level                       = "High"
						}
					}
					`, rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingPolicy("banyan_policy_web.example", &bnnPolicy),
					resource.TestCheckResourceAttr("banyan_policy_web.example", "name", rName),
					resource.TestCheckResourceAttrPtr("banyan_policy_web.example", "id", &bnnPolicy.ID),
					testAccCheckPolicyAgainstJson(t, testAccPolicy_web_basic_create_json(rName), &bnnPolicy.ID),
				),
			},
		},
	})
}

func testAccPolicy_web_basic_create_json(name string) string {
	return fmt.Sprintf(`
{
    "kind": "BanyanPolicy",
    "apiVersion": "rbac.banyanops.com/v1",
    "metadata": {
        "name": "%s",
        "description": "some web policy description",
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
                    "l7_access": [
                        {
                            "resources": [
                                "*"
                            ],
                            "actions": [
                                "*"
                            ]
                        }
                    ],
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
            "disable_tls_client_authentication": true,
            "l7_protocol": "http"
        }
    }
}
    `, name)
}

func TestAccPolicy_web_l7(t *testing.T) {
	var bnnPolicy policy.GetPolicy

	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckPolicy_destroy(t, &bnnPolicy.ID),
		Steps: []resource.TestStep{
			// Create the policy using terraform config and check that it exists
			{
				Config: testAccPolicy_web_l7_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingPolicy("banyan_policy_web.example", &bnnPolicy),
					testAccCheckPolicyAgainstJson(t, testAccPolicy_web_l7_create_json(rName), &bnnPolicy.ID),
				),
			},
		},
	})
}

// Checks that the resource with the name resourceName exists and returns the role object from the Banyan API
func testAccCheckExistingPolicy(resourceName string, bnnPolicy *policy.GetPolicy) resource.TestCheckFunc {
	return func(s *terraform.State) error {

		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found %q", rs)
		}
		resp, err := testAccClient.Policy.Get(rs.Primary.ID)
		if err != nil {
			return err
		}
		if resp.ID != rs.Primary.ID {
			return fmt.Errorf("expected resource id %q got %q instead", resp.ID, rs.Primary.ID)
		}
		*bnnPolicy = resp
		return nil
	}
}

// Uses the API to check that the policy was destroyed
func testAccCheckPolicy_destroy(t *testing.T, id *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		r, _ := testAccClient.Policy.Get(*id)
		assert.Equal(t, r.ID, "")
		return nil
	}
}

// Returns terraform configuration for the policy
func testAccPolicy_web_l7_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_policy_web" "example" {
  name        = "%s"
  description = "some web policy description"
  access {
    roles       = ["Everyone"]
    trust_level = "High"
    l7_access {
      resources = ["/admin"]
      actions   = ["READ"]
    }
  }
}
`, name)
}

func testAccPolicy_web_l7_create_json(name string) string {
	return fmt.Sprintf(`
{
  "kind": "BanyanPolicy",
  "apiVersion": "rbac.banyanops.com/v1",
  "metadata": {
    "name": "%s",
    "description": "some web policy description",
    "tags": {
      "template": "USER"
    }
  },
  "type": "USER",
  "spec": {
    "access": [
      {
        "roles": [
          "Everyone"
        ],
        "rules": {
          "l7_access": [
            {
              "resources": [
                "/admin"
              ],
              "actions": [
                "READ"
              ]
            }
          ],
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
      "disable_tls_client_authentication": true,
      "l7_protocol": "http"
    }
  }
}
`, name)
}
