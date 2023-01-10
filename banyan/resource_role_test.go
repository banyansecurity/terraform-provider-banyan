package banyan

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/banyansecurity/terraform-banyan-provider/client/role"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/assert"
)

func TestSchemaRole_known_device(t *testing.T) {
	role_known_device := map[string]interface{}{
		"name":              "UsersRegisteredDevice",
		"description":       "[TF] Users on a device registered with Banyan",
		"user_group":        []interface{}{"Users"},
		"known_device_only": true,
	}
	d := schema.TestResourceDataRaw(t, RoleSchema(), role_known_device)
	role_obj := RoleFromState(d)

	json_spec, _ := ioutil.ReadFile("./specs/role/known-device.json")
	var ref_obj role.CreateRole
	_ = json.Unmarshal([]byte(json_spec), &ref_obj)

	AssertCreateRoleEqual(t, role_obj, ref_obj)
}

func TestSchemaRole_device_ownership(t *testing.T) {
	role_device_ownership := map[string]interface{}{
		"name":             "AdminsCorpDevice",
		"description":      "[TF] Admins on corporate devices",
		"user_group":       []interface{}{"Admins"},
		"device_ownership": []interface{}{"Corporate Dedicated", "Corporate Shared"},
	}
	d := schema.TestResourceDataRaw(t, RoleSchema(), role_device_ownership)
	role_obj := RoleFromState(d)

	json_spec, _ := ioutil.ReadFile("./specs/role/device-ownership.json")
	var ref_obj role.CreateRole
	_ = json.Unmarshal([]byte(json_spec), &ref_obj)

	AssertCreateRoleEqual(t, role_obj, ref_obj)
}

func TestAccRole_basic(t *testing.T) {
	var bnnRole role.GetRole

	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckRoleDestroy(t, &bnnRole.ID),
		Steps: []resource.TestStep{
			// Creates the role with the given terraform configuration and asserts that the role is created
			{
				Config: testAccRole_basic_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingRole("banyan_role.acceptance", &bnnRole),
					resource.TestCheckResourceAttr("banyan_role.acceptance", "name", rName),
					resource.TestCheckResourceAttrPtr("banyan_role.acceptance", "id", &bnnRole.ID),
				),
			},
			{
				ResourceName:      "banyan_role.acceptance",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccRole_complex(t *testing.T) {
	var bnnRole role.GetRole

	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckRoleDestroy(t, &bnnRole.ID),
		Steps: []resource.TestStep{
			// Creates the role with the given terraform configuration and asserts that the role is created
			{
				Config: testAccRole_complex_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingRole("banyan_role.acceptance", &bnnRole),
					resource.TestCheckResourceAttr("banyan_role.acceptance", "name", rName),
					resource.TestCheckResourceAttrPtr("banyan_role.acceptance", "id", &bnnRole.ID),
				),
			},
			{
				ResourceName:      "banyan_role.acceptance",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Updates the same role with a different configuration and asserts that the same role was updated correctly
			{
				Config: testAccRole_complex_update(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingRole("banyan_role.acceptance", &bnnRole),
					testAccCheckRoleGroupsUpdated(t, &bnnRole, []string{"group1", "group2"}),
					resource.TestCheckResourceAttrPtr("banyan_role.acceptance", "id", &bnnRole.ID),
				),
			},
			{
				ResourceName:      "banyan_role.acceptance",
				ImportState:       true,
				ImportStateVerify: true,
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
		resp, err := testAccClient.Role.Get(rs.Primary.ID)
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
		if !assert.ElementsMatch(t, bnnRole.UnmarshalledSpec.Spec.UserGroup, group) {
			return fmt.Errorf("incorrect groups, expected %s, got: %s", group, bnnRole.UnmarshalledSpec.Spec.UserGroup)
		}
		return nil
	}
}

// Uses the API to check that the role was destroyed
func testAccCheckRoleDestroy(t *testing.T, id *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		r, _ := testAccClient.Role.Get(*id)
		assert.Equal(t, r.ID, "")
		return nil
	}
}

// Returns terraform configuration for the role. Takes in custom name.
func testAccRole_basic_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_role" "acceptance" {
  name              = "%s"
  description       = "realdescription"
  user_group        = ["group1"]
  device_ownership  = ["Corporate Dedicated", "Corporate Shared", "Employee Owned", "Other"]
  known_device_only = true
  mdm_present       = true
  platform          = ["Windows", "macOS", "Linux", "iOS", "Android", "Unregistered"]
}
`, name)
}

func testAccRole_complex_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_role" "acceptance" {
 name = %q
  description = "realdescription"
  container_fqdn = ["asdf.asdf"]
  known_device_only = true
  platform = ["macOS", "Android"]
  user_group = ["group1"]
  email = ["john@marsha.com"]
  device_ownership = ["Corporate Dedicated", "Employee Owned"]
  mdm_present = true
}
`, name)
}

// Returns terraform configuration for an updated version of the role with additional groups. Takes in custom name.
func testAccRole_complex_update(name string) string {
	return fmt.Sprintf(`
resource "banyan_role" "acceptance" {
 name = %q
  description = "realdescription"
  container_fqdn = ["asdf.asdf"]
  known_device_only = true
  platform = ["macOS", "Android"]
  user_group = ["group1", "group2"]
  email = ["john@marsha.com"]
  device_ownership = ["Corporate Dedicated", "Employee Owned"]
  mdm_present = true
}
`, name)
}
