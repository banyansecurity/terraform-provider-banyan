package banyan

import (
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/servicetunnel"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/assert"
	"testing"
)

// Use the terraform plugin sdk testing framework for example testing accesstier lifecycle
func TestAccAccessTier_basic(t *testing.T) {
	var bnnAccessTier servicetunnel.AccessTierInfo

	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAccessTierDestroy(t, "banyan_accesstier.example"),
		Steps: []resource.TestStep{
			// Creates the accesstier with the given terraform configuration and asserts that the accesstier is created
			{
				Config: testAccAccessTier_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingAccessTier("banyan_accesstier.example", &bnnAccessTier),
					resource.TestCheckResourceAttr("banyan_accesstier.example", "name", rName),
					resource.TestCheckResourceAttrPtr("banyan_accesstier.example", "id", &bnnAccessTier.ID),
				),
			},
			{
				Config: testAccAccessTier_update(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingAccessTier("banyan_accesstier.example", &bnnAccessTier),
					resource.TestCheckResourceAttr("banyan_accesstier.example", "name", rName),
					resource.TestCheckResourceAttrPtr("banyan_accesstier.example", "id", &bnnAccessTier.ID),
				),
			},
		},
	})
}

// Checks that the resource with the name resourceName exists and returns the accesstier object from the Banyan API
func testAccCheckExistingAccessTier(resourceName string, bnnAccessTier *servicetunnel.AccessTierInfo) resource.TestCheckFunc {
	return func(s *terraform.State) error {

		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found in state %q", rs)
		}
		resp, err := testAccClient.AccessTier.Get(rs.Primary.ID)
		if err != nil {
			return err
		}
		if resp.ID != rs.Primary.ID {
			return fmt.Errorf("expected resource id %q got %q instead", resp.ID, rs.Primary.ID)
		}
		*bnnAccessTier = resp
		return nil
	}
}

// Uses the API to check that the accesstier was destroyed
func testAccCheckAccessTierDestroy(t *testing.T, resourceName string) resource.TestCheckFunc {
	emptyAccessTier := servicetunnel.AccessTierInfo{}
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found in state %q", rs)
		}
		r, _ := testAccClient.AccessTier.Get(rs.Primary.ID)
		assert.Equal(t, r, emptyAccessTier)
		return nil
	}
}

// Returns terraform configuration for the accesstier. Takes in custom name.
func testAccAccessTier_create(name string) string {
	return fmt.Sprintf(`
resource banyan_accesstier "example" {
  name = "%s"
  cluster = "us-west"
  address = "*.example.com"
  domains = ["*.example.com"]
}
`, name)
}

func testAccAccessTier_update(name string) string {
	return fmt.Sprintf(`
resource banyan_accesstier "example" {
  name = "%s"
  cluster = "us-west"
  address = "*.example.com"
  domains = ["*.example.com"]
  connector_tunnel_port = 3857
  end_user_tunnel_port = 3858
  end_user_tunnel_backend_cidrs = ["10.10.10.0/24"]
  end_user_tunnel_private_domains = ["corp.internal"]
  end_user_tunnel_enable_private_dns = true
}
`, name)
}
