package banyan

import (
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/apikey"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/assert"
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

// Checks that the resource with the name resourceName exists and returns the apikey object from the Banyan API
func testAccCheckExistingApiKey(resourceName string, bnnApiKey *apikey.Data) resource.TestCheckFunc {
	return func(s *terraform.State) error {

		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found %q", rs)
		}
		resp, err := testAccClient.ApiKey.Get(bnnApiKey.ID)
		if err != nil {
			return err
		}
		if resp.ID != rs.Primary.ID {
			return fmt.Errorf("expected resource id %q got %q instead", resp.ID, rs.Primary.ID)
		}
		*bnnApiKey = resp
		return nil
	}
}

// Uses the API to check that the apikey was destroyed
func testAccCheckApiKeyDestroy(t *testing.T, name *string) resource.TestCheckFunc {
	emptyApiKey := apikey.Data{}
	return func(s *terraform.State) error {
		r, err := testAccClient.ApiKey.Get(*name)
		assert.Equal(t, r, emptyApiKey)
		return err
	}
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
