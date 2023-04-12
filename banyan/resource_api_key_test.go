package banyan

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"testing"
)

// Use the terraform plugin sdk testing framework for example testing apikey lifecycle
func TestAccApiKey_basic(t *testing.T) {

	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: nil,
		Steps: []resource.TestStep{
			// Creates the apikey with the given terraform configuration and asserts that the apikey is created
			{
				Config: testAccApiKey_basic_create(rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("banyan_api_key.example", "name", rName),
				),
			},
		},
	})
}

func TestAccApiKey_update(t *testing.T) {

	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: nil,
		Steps: []resource.TestStep{
			// Creates the apikey with the given terraform configuration and asserts that the apikey is created
			{
				Config: testAccApiKey_basic_create(rName),
				Check:  resource.ComposeTestCheckFunc(),
			},
			{
				Config: testAccApiKey_basic_update(fmt.Sprintf("%s-new", rName)),
				Check:  resource.ComposeTestCheckFunc(),
			},
		},
	})
}

// Returns terraform configuration for the apikey. Takes in custom name.
func testAccApiKey_basic_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_api_key" "example" {
  name              = "%s"
  description       = "realdescription"
  scope             = "satellite"
}
`, name)
}

// Returns terraform configuration for the apikey. Takes in custom name.
func testAccApiKey_basic_update(name string) string {
	return fmt.Sprintf(`
resource "banyan_api_key" "example" {
  name              = "%s-update"
  description       = "some description"
  scope             = "satellite"
}

resource "banyan_api_key" "example2" {
  name              = "%s"
  description       = "some description"
  scope             = "satellite"
}
`, name, name)
}
