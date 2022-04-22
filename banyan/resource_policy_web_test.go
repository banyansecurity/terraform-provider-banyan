package banyan

import (
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/policy"
	"github.com/banyansecurity/terraform-banyan-provider/client/role"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/assert"
	"testing"
)

// Use the Terraform plugin SDK testing framework for acceptance testing banyan policy lifecycle.
func TestAccPolicy_web_basic(t *testing.T) {
	var bnnPolicy policy.GetPolicy

	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckPolicy_destroy(t, &bnnPolicy.ID),
		Steps: []resource.TestStep{
			// Create the policy using terraform config and check that it exists
			{
				Config: testAccPolicy_web_basic_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingPolicy("banyan_policy_web.example", &bnnPolicy),
					resource.TestCheckResourceAttr("banyan_policy_web.example", "name", rName),
					resource.TestCheckResourceAttrPtr("banyan_policy_web.example", "id", &bnnPolicy.ID),
				),
			},
		},
	})
}

func TestAccPolicy_web_l7(t *testing.T) {
	var bnnPolicy policy.GetPolicy

	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckPolicy_destroy(t, &bnnPolicy.ID),
		Steps: []resource.TestStep{
			// Create the policy using terraform config and check that it exists
			{
				Config: testAccPolicy_web_l7_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingPolicy("banyan_policy_web.example", &bnnPolicy),
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
		resp, _, err := testAccClient.Policy.Get(rs.Primary.ID)
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
	emptyRole := role.GetRole{}
	return func(s *terraform.State) error {
		r, _, err := testAccClient.Role.Get(*id)
		assert.Equal(t, r, emptyRole)
		return err
	}
}

// Returns terraform configuration for the policy
func testAccPolicy_web_basic_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_policy_web" "example" {
  name        = %q
  description = "some web policy description"
  access {
    roles                             = ["ANY", "HI"]
    trust_level                       = "High"
  }
}
`, name)
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
    l7_resources = ["/admin"]
    l7_actions   = ["READ"]
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
          "mviux78efi",
          "k3cv0yir0l"
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
            "trust_level": "Medium"
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
