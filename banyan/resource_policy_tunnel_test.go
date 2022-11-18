package banyan

import (
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/policy"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"testing"
)

// Use the Terraform plugin SDK testing framework for acceptance testing banyan policy lifecycle.
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
							l4_access_allow {
								cidrs = ["10.10.10.0/24"]
								protocols = ["UDP"]
								ports = ["80"]
							}
						}
					}
					`, rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingPolicy("banyan_policy_tunnel.example", &bnnPolicy),
					testAccCheckPolicyAgainstJson(t, testAccPolicy_tunnel_l4_create_json(rName), &bnnPolicy.ID),
				),
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
                    }
                }
            }
        ]
    }
}
`, name)
}
