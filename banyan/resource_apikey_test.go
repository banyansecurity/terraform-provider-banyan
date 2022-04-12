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
	var bnnApiKey apikey.Data

	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckApiKeyDestroy(t, &bnnApiKey.Name),
		Steps: []resource.TestStep{
			// Creates the apikey with the given terraform configuration and asserts that the apikey is created
			{
				Config: testAccApiKey_basic_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingApiKey("banyan_apikey.example", rName, &bnnApiKey),
					resource.TestCheckResourceAttr("banyan_apikey.example", "name", rName),
					resource.TestCheckResourceAttrPtr("banyan_apikey.example", "id", &bnnApiKey.ID),
				),
			},
		},
	})
}

// Checks that the resource with the name resourceName exists and returns the apikey object from the Banyan API
func testAccCheckExistingApiKey(resourceName string, name string, bnnApiKey *apikey.Data) resource.TestCheckFunc {
	return func(s *terraform.State) error {

		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found %q", rs)
		}
		resp, err := testAccClient.ApiKey.Get(name)
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
resource "banyan_apikey" "example" {
  name              = "%s"
  description       = "realdescription"
  scope             = "satellite"
}
`, name)
}
