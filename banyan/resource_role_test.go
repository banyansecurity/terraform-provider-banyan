package banyan

import (
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/role"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/assert"
	"testing"
)

// Use the terraform plugin sdk testing framework for acceptance testing role lifecycle
func TestAccRole_basic(t *testing.T) {
	var bnnRole role.GetRole

	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckRoleDestroy(t, &bnnRole.ID),
		Steps: []resource.TestStep{
			// Creates the role with the given terraform configuration and asserts that the role is created
			{
				Config: testAccRole_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingRole("banyan_role.acceptance", &bnnRole),
					resource.TestCheckResourceAttr("banyan_role.acceptance", "name", rName),
					resource.TestCheckResourceAttrPtr("banyan_role.acceptance", "id", &bnnRole.ID),
				),
			},
			// Updates the same role with a different configuration and asserts that the same role was updated correctly
			{
				Config: testAccRole_update(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingRole("banyan_role.acceptance", &bnnRole),
					testAccCheckRoleGroupsUpdated(t, &bnnRole, []string{"group1", "group2"}),
					resource.TestCheckResourceAttrPtr("banyan_role.acceptance", "id", &bnnRole.ID),
				),
			},
		},
	})
}

// Checks that the resource with the name resourceName exists and returns the role object from the Banyan API
func testAccCheckExistingRole(resourceName string, bnnRole *role.GetRole) resource.TestCheckFunc {
	return func(s *terraform.State) error {

		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found %q", rs)
		}
		resp, _, err := testAccClient.Role.Get(rs.Primary.ID)
		if err != nil {
			return err
		}
		if resp.ID != rs.Primary.ID {
			return fmt.Errorf("expected resource id %q got %q instead", resp.ID, rs.Primary.ID)
		}
		*bnnRole = resp
		return nil
	}
}

// Asserts using the API that the groups for the role were updated
func testAccCheckRoleGroupsUpdated(t *testing.T, bnnRole *role.GetRole, group []string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if !assert.ElementsMatch(t, bnnRole.UnmarshalledSpec.Spec.Group, group) {
			return fmt.Errorf("incorrect groups, expected %s, got: %s", group, bnnRole.UnmarshalledSpec.Spec.Group)
		}
		return nil
	}
}

// Uses the API to check that the role was destroyed
func testAccCheckRoleDestroy(t *testing.T, id *string) resource.TestCheckFunc {
	emptyRole := role.GetRole{}
	return func(s *terraform.State) error {
		r, _, err := testAccClient.Role.Get(*id)
		assert.Equal(t, r, emptyRole)
		return err
	}
}

// Returns terraform configuration for the role. Takes in custom name.
func testAccRole_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_role" "acceptance" {
 name = %q
  description = "realdescription"
  metadatatags {
    template = "USER"
  }
  spec {
    known_device_only = true
    platform = ["macOS", "Android"]
    group = ["group1"]
    email = ["john@marsha.com"]
    device_ownership = ["Corporate Dedicated", "Employee Owned"]
    mdm_present = true
  }
}
`, name)
}

// Returns terraform configuration for an updated version of the role with additional groups. Takes in custom name.
func testAccRole_update(name string) string {
	return fmt.Sprintf(`
resource "banyan_role" "acceptance" {
 name = %q
  description = "realdescriptionnn"
  metadatatags {
    template = "USER"
  }
  spec {
    known_device_only = true
    platform = ["macOS", "Android"]
    group = ["group1", "group2"]
    email = ["john@marsha.com"]
    device_ownership = ["Corporate Dedicated", "Employee Owned"]
    mdm_present = true
  }
}
`, name)
}
