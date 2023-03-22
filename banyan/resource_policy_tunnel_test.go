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
)

func TestSchemaPolicyTunnel_l4(t *testing.T) {
	access1 := map[string]interface{}{
		"roles":       []interface{}{"UsersRegisteredDevice"},
		"trust_level": "Low",
		"l4_access": []interface{}{
			map[string]interface{}{
				"allow": []interface{}{
					map[string]interface{}{
						"cidrs":     []interface{}{"10.138.0.14/32", "10.138.0.11/32", "10.10.0.0/16"},
						"protocols": []interface{}{"ALL"},
						"ports":     []interface{}{"*"},
						"fqdns":     []interface{}{},
					},
				},
				"deny": []interface{}{
					map[string]interface{}{
						"cidrs":     []interface{}{"10.10.1.0/24", "10.10.2.0/24"},
						"protocols": []interface{}{"TCP"},
						"ports":     []interface{}{"22"},
						"fqdns":     []interface{}{},
					},
				},
			},
		},
	}

	access2 := map[string]interface{}{
		"roles":       []interface{}{"AdminsCorpDevice"},
		"trust_level": "High",
	}

	policy_l4 := map[string]interface{}{
		"name":        "Datacenter w L4 Controls",
		"description": "[TF] Restrict ordinary users to filesharing and Windows servers",
		"access":      []interface{}{access1, access2},
	}
	d := schema.TestResourceDataRaw(t, PolicyTunnelSchema(), policy_l4)
	policy_obj := policyTunnelFromState(d)

	json_spec, _ := ioutil.ReadFile("./specs/policy/l4.json")
	var ref_obj policy.Object
	_ = json.Unmarshal([]byte(json_spec), &ref_obj)

	AssertPolicySpecEqual(t, policy_obj, ref_obj)
}

func TestAccPolicy_tunnel_basic(t *testing.T) {
	var bnnPolicy policy.GetPolicy

	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckPolicy_destroy(t, &bnnPolicy.ID),
		Steps: []resource.TestStep{
			// Create the policy using terraform config and check that it exists
			{
				Config: fmt.Sprintf(`
                    resource "banyan_policy_tunnel" "example" {
                            name        = %q
                            description = "some tunnel policy description"
                            access {
                            roles                             = ["ANY", "HI"]
                            trust_level                       = "High"
                        }
                    }
                    `, rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingPolicy("banyan_policy_tunnel.example", &bnnPolicy),
					resource.TestCheckResourceAttr("banyan_policy_tunnel.example", "name", rName),
					resource.TestCheckResourceAttrPtr("banyan_policy_tunnel.example", "id", &bnnPolicy.ID),
				),
			},
		},
	})
}

func TestAccPolicy_tunnel_l4(t *testing.T) {
	var bnnPolicy policy.GetPolicy

	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckPolicy_destroy(t, &bnnPolicy.ID),
		Steps: []resource.TestStep{
			// Create the policy using terraform config and check that it exists
			{
				Config: fmt.Sprintf(`
                    resource "banyan_policy_tunnel" "example" {
                      name        = "%s"
                      description = "some tunnel policy description"
                      access {
                        roles       = ["Everyone"]
                        trust_level = "Low"
                        l4_access {
                          allow {
                            cidrs = ["10.10.10.0/24"]
                            protocols = ["UDP"]
                            ports = ["80"]
                            fqdns = ["www.example.com"]
                          }
                          deny {
                            cidrs = ["10.10.11.0/24"]
                            protocols = ["TCP"]
                            ports = ["80"]
                            fqdns = ["www.deny.com"]
                          }
                        }
                      }
                    }
                    `, rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingPolicy("banyan_policy_tunnel.example", &bnnPolicy),
					testAccCheckPolicyAgainstJson(t, testAccPolicy_tunnel_l4_create_json(rName), &bnnPolicy.ID),
				),
			},
			{
				ResourceName:      "banyan_policy_tunnel.example",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccPolicy_tunnel_l4_create_json(name string) string {
	return fmt.Sprintf(`
{
    "kind": "BanyanPolicy",
    "apiVersion": "rbac.banyanops.com/v1",
    "metadata": {
        "name": "%s",
        "description": "some tunnel policy description",
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
                    "conditions": {
                        "trust_level": "Low"
                    },
                    "l4_access": {
                        "allow": [
                            {
                                "cidrs": [
                                    "10.10.10.0/24"
                                ],
                                "ports": [
                                    "80"
                                ],
                                "protocols": [
                                    "UDP"
                                ],
                                "fqdns": [
                                    "www.example.com"	
                                ]
                            }
                        ],
                        "deny": [
                            {
                                "cidrs": [
                                    "10.10.11.0/24"
                                ],
                                "ports": [
                                    "80"
                                ],
                                "protocols": [
                                    "TCP"
                                ],
                                "fqdns": [
                                    "www.deny.com"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    }
}
`, name)
}

func TestAccPolicy_tunnel_any(t *testing.T) {
	var bnnPolicy policy.GetPolicy

	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckPolicy_destroy(t, &bnnPolicy.ID),
		Steps: []resource.TestStep{
			// Create the policy using terraform config and check that it exists
			{
				Config: fmt.Sprintf(`
                    resource "banyan_policy_tunnel" "example" {
                        name        = "%s"
                        description = "some tunnel policy description"
                        access {
                            roles       = ["Everyone"]
                            trust_level = "High"
                        }
                    }
                    `, rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingPolicy("banyan_policy_tunnel.example", &bnnPolicy),
					testAccCheckPolicyAgainstJson(t, testAccPolicy_tunnel_any_create_json(rName), &bnnPolicy.ID),
				),
			},
			{
				ResourceName:      "banyan_policy_tunnel.example",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccPolicy_tunnel_any_create_json(name string) string {
	return fmt.Sprintf(`
{
    "kind": "BanyanPolicy",
    "apiVersion": "rbac.banyanops.com/v1",
    "metadata": {
        "name": "%s",
        "description": "some tunnel policy description",
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
                    "conditions": {
                        "trust_level": "High"
                    },
                    "l4_access": {
                        "allow": [
                            {
                                "cidrs": [
                                    "*"
                                ],
                                "ports": [
                                    "*"
                                ],
                                "protocols": [
                                    "ALL"
                                ]
                            }
                        ]
                    }
                }
            }
        ]
    }
}
`, name)
}
