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
func TestAccPolicy_basic(t *testing.T) {
	var bnnPolicy policy.GetPolicy

	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckPolicy_destroy(t, &bnnPolicy.ID),
		Steps: []resource.TestStep{
			// Create the policy using terraform config and check that it exists
			{
				Config: testAccPolicy_basic_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingPolicy("banyan_policy.acceptance", &bnnPolicy),
					resource.TestCheckResourceAttr("banyan_policy.acceptance", "name", rName),
					resource.TestCheckResourceAttrPtr("banyan_policy.acceptance", "id", &bnnPolicy.ID),
				),
			},
		},
	})
}

func TestAccPolicy_web(t *testing.T) {
	var bnnPolicy policy.GetPolicy

	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckPolicy_destroy(t, &bnnPolicy.ID),
		Steps: []resource.TestStep{
			// Create the policy using terraform config and check that it exists
			{
				Config: testAccPolicy_web_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingPolicy("banyan_policy.web-policy", &bnnPolicy),
				),
			},
		},
	})
}

func TestAccPolicy_infrastructure(t *testing.T) {
	var bnnPolicy policy.GetPolicy

	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckPolicy_destroy(t, &bnnPolicy.ID),
		Steps: []resource.TestStep{
			// Create the policy using terraform config and check that it exists
			{
				Config: testAccPolicy_infrastructure_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingPolicy("banyan_policy.infrastructure-policy", &bnnPolicy),
				),
			},
		},
	})
}

func TestAccPolicy_complex(t *testing.T) {
	var bnnPolicy policy.GetPolicy

	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckPolicy_destroy(t, &bnnPolicy.ID),
		Steps: []resource.TestStep{
			// Create the policy using terraform config and check that it exists
			{
				Config: testAccPolicy_complex_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingPolicy("banyan_policy.acceptance", &bnnPolicy),
					resource.TestCheckResourceAttr("banyan_policy.acceptance", "name", rName),
					resource.TestCheckResourceAttrPtr("banyan_policy.acceptance", "id", &bnnPolicy.ID),
				),
			},
			// Update the policy using terraform config and ensure the update was applied correctly
			{
				Config: testAccPolicy_complex_update(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingPolicy("banyan_policy.acceptance", &bnnPolicy),
					testAccCheckPolicyAccessUpdated(t, &bnnPolicy, []string{"ANY"}),
					resource.TestCheckResourceAttrPtr("banyan_policy.acceptance", "id", &bnnPolicy.ID),
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

// Asserts using the API that the roles for the policy were updated
func testAccCheckPolicyAccessUpdated(t *testing.T, bnnPolicy *policy.GetPolicy, roles []string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if !assert.ElementsMatch(t, bnnPolicy.UnmarshalledPolicy.Spec.Access[0].Roles, roles) {
			return fmt.Errorf("incorrect exceptions, expected %s, got: %s", roles, bnnPolicy.UnmarshalledPolicy.Spec.Access)
		}
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
func testAccPolicy_basic_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_policy" "acceptance" {
  name        = %q
  description = "realdescription"
  type = "USER"
  access {
    roles                             = ["ANY", "HI"]
    trust_level                       = "High"
  }
}
`, name)
}

// Returns terraform configuration for the policy
func testAccPolicy_web_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_policy" "web-policy" {
  name        = "%s"
  description = "some web policy description"
  access {
    roles       = ["Everyone"]
    trust_level = "High"
    l7_access {
      resources = ["*"]
      actions   = ["*"]
    }
  }
  l7_protocol                       = "http"
  disable_tls_client_authentication = true
}
`, name)
}

// Returns terraform configuration for the policy
func testAccPolicy_infrastructure_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_policy" "infrastructure-policy" {
  name        = "%s"
  description = "some infrastructure policy description"
  access {
    roles       = ["Everyone"]
    trust_level = "High"
  }
  disable_tls_client_authentication = false
}
`, name)
}

// Returns terraform configuration for the policy
func testAccPolicy_complex_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_policy" "acceptance" {
  name        = %q
  description = "realdescription"
  metadatatags {
    template = "USER"
  }
  type = "USER"
  access {
    roles                             = ["ANY", "HI"]
    trust_level                       = "High"
    l7_access {
      resources = ["*"]
      actions   = ["*"]
    }
  }
  disable_tls_client_authentication = true
  l7_protocol                       = "http"
}
`, name)
}

// Returns an updated terraform configuration for the policy with one of the roles removed
func testAccPolicy_complex_update(name string) string {
	return fmt.Sprintf(`
resource "banyan_policy" "acceptance" {
  name        = %q
  description = "realdescription"
  metadatatags {
    template = "USER"
  }
  type = "USER"
  access {
    roles                             = ["ANY"]
    trust_level                       = "High"
    l7_access {
      resources = ["*"]
      actions   = ["*"]
    }
  }
  disable_tls_client_authentication = true
  l7_protocol                       = "http"
}
`, name)
}
