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

// The required test is used to test the lifecycle of a resource with only the required parameters set
func TestAccAccessTier_required(t *testing.T) {
	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
	r := accesstier.AccessTierInfo{}

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAccessTierDestroy(t, "banyan_accesstier.example"),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
					resource "banyan_api_key" "example" {
						name              = "%s"
						description       = "realdescription"
						scope             = "access_tier"
					}
					resource banyan_accesstier "example" {
						name = "%s"
						address = "*.example.com"
						api_key_id = banyan_api_key.example.id
					}
					`, rName, rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAccessTierExists("banyan_accesstier.example", &r),
				),
			},
			{
				ResourceName:      "banyan_accesstier.example",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: fmt.Sprintf(`
					resource "banyan_api_key" "example" {
						name              = "%s"
						description       = "realdescription"
						scope             = "access_tier"
					}
					resource banyan_accesstier "example" {
						name = "%s"
						address = "*.example.com"
						api_key_id = banyan_api_key.example.id
					}
					`, rName, rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAccessTierExists("banyan_accesstier.example", &r),
				),
			},
			{
				ResourceName:      "banyan_accesstier.example",
				ImportState:       true,
				ImportStateVerify: true,
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
				Config: fmt.Sprintf(`
					resource "banyan_api_key" "example" {
						name              = "%s"
						description       = "realdescription"
						scope             = "access_tier"
					}

					resource banyan_accesstier "example" {
						name = "%s"
						address = "*.example.com"
						api_key_id = banyan_api_key.example.id
						tunnel_connector_port = 39103
						tunnel_cidrs = ["10.0.2.0/16"]
						tunnel_private_domains = ["test.com"]
						enable_hsts = true
						forward_trust_cookie = true
						events_rate_limiting = true
						event_key_rate_limiting = true
                        statsd_address = "10.0.3.5"
					}
					`, rName, rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAccessTierExists("banyan_accesstier.example", &r),
				),
			},
			{
				ResourceName:      "banyan_accesstier.example",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: fmt.Sprintf(`
					resource "banyan_api_key" "example" {
						name              = "%s"
						description       = "realdescription"
						scope             = "access_tier"
					}

					resource banyan_accesstier "example" {
						name = "%s"
						address = "*.exampletwo.com"
						api_key_id = banyan_api_key.example.id
						tunnel_connector_port = 39104
						tunnel_cidrs = ["10.0.3.0/16"]
						tunnel_private_domains = ["example.com"]
						enable_hsts = false
						forward_trust_cookie = true
						events_rate_limiting = true
						event_key_rate_limiting = true
                        statsd_address = "10.0.3.6"
					}
					`, rName, rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAccessTierExists("banyan_accesstier.example", &r),
				),
			},
			{
				ResourceName:      "banyan_accesstier.example",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccCheckAccessTierExists(resourceName string, r *accesstier.AccessTierInfo) resource.TestCheckFunc {
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
		r, _ := testAccClient.AccessTier.Get(resourceName)
		assert.Equal(t, r, emptyAccessTier)
		return nil
	}
}
