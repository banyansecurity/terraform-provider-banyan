package banyan

import (
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/accesstier"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/assert"
	"testing"
)

const apiKeyID = "f0da9734-10b7-4ace-85ae-05206119cc69"

// The required test is used to test the lifecycle of a resource with only the required parameters set
func TestAccAccessTier_required(t *testing.T) {
	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	r := accesstier.AccessTierInfo{}

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAccessTierDestroy(t, "banyan_accesstier.example"),
		Steps: []resource.TestStep{
			{
				Config: testAccAccessTier_create_required(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExists("banyan_accesstier.example", &r),
				),
			},
			{
				Config: testAccAccessTier_update_required(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExists("banyan_accesstier.example", &r),
				),
			},
		},
	})
}

// The optional test is used to test the lifecycle of a resource with the required parameters and optional parameters set
func TestAccAccessTier_optional(t *testing.T) {
	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	r := accesstier.AccessTierInfo{}

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAccessTierDestroy(t, "banyan_accesstier.example"),
		Steps: []resource.TestStep{
			{
				Config: testAccAccessTier_create_optional(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExists("banyan_accesstier.example", &r),
				),
			},
			{
				Config: testAccAccessTier_update_optional(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExists("banyan_accesstier.example", &r),
				),
			},
		},
	})
}

func testAccCheckExists(resourceName string, r *accesstier.AccessTierInfo) resource.TestCheckFunc {
	return func(s *terraform.State) (err error) {
		err = testAccCheckExistingAccessTier(resourceName, r, s)
		if err != nil {
			return err
		}
		return
	}
}

// Checks that the resource with the name resourceName exists and returns the resource object from the Banyan API
func testAccCheckExistingAccessTier(resourceName string, bnnAccessTier *accesstier.AccessTierInfo, s *terraform.State) (err error) {
	rs, ok := s.RootModule().Resources[resourceName]
	if !ok {
		return fmt.Errorf("resource not found in state %s", resourceName)
	}
	resp, err := testAccClient.AccessTier.Get(rs.Primary.ID)
	if err != nil {
		return fmt.Errorf("could not get resource from API %s id: %s", resourceName, rs.Primary.ID)
	}
	*bnnAccessTier = resp
	return
}

// Uses the API to check that the accesstier was destroyed
func testAccCheckAccessTierDestroy(t *testing.T, resourceName string) resource.TestCheckFunc {
	emptyAccessTier := accesstier.AccessTierInfo{}
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

// Returns terraform configuration with the required parameters set
func testAccAccessTier_create_required(name string) string {
	return fmt.Sprintf(`
resource banyan_accesstier "example" {
  name = "%s"
  address = "*.example.com"
  cluster = "tortoise"
  api_key_id = "%s"
}
`, name, apiKeyID)
}

// Returns terraform configuration with the required parameters updated
func testAccAccessTier_update_required(name string) string {
	return fmt.Sprintf(`
resource banyan_accesstier "example" {
  name = "%s-updated"
  address = "*.updated.com"
  cluster = "updated"
  api_key_id = "%s"
}
`, name, apiKeyID)
}

// Returns terraform configuration with the required and optional parameters set
func testAccAccessTier_create_optional(name string) string {
	return fmt.Sprintf(`
resource banyan_accesstier "example" {
  name = "%s"
  address = "*.example.com"
  cluster = "tortoise"
  api_key_id = "%s"
  tunnel_connector {
    port = 39103
  }
  tunnel_enduser {
    port = 39104
    cidrs = ["10.0.2.0/16"]
    domains = ["corp.internal"]
  }
}
`, name, apiKeyID)
}

// Returns terraform configuration with the required and optional
// parameters updated ('ForceNew' elements should be omitted)
func testAccAccessTier_update_optional(name string) string {
	return fmt.Sprintf(`
resource banyan_accesstier "example" {
  name = "%s"
  address = "*.updated.com"
  cluster = "tortoise"
  api_key_id = "%s"
  tunnel_connector {
    port = 39104
  }
  tunnel_enduser {
    port = 39105
    cidrs = ["10.0.3.0/16"]
    domains = ["corpupdated.internal"]
  }
}
`, name, apiKeyID)
}
