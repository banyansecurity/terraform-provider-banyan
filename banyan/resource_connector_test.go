package banyan

import (
	"fmt"
	"testing"

	"github.com/banyansecurity/terraform-banyan-provider/client/satellite"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/assert"
)

// Use the terraform plugin sdk testing framework for example testing connector lifecycle
func TestAccConnector_basic(t *testing.T) {
	var bnnConnector satellite.SatelliteTunnelConfig

	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckConnectorDestroy(t, "banyan_connector.example"),
		Steps: []resource.TestStep{
			// Creates the connector with the given terraform configuration and asserts that the connector is created
			{
				Config: testAccConnector_basic_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingConnector("banyan_connector.example", &bnnConnector),
					resource.TestCheckResourceAttr("banyan_connector.example", "name", rName),
					resource.TestCheckResourceAttrPtr("banyan_connector.example", "id", &bnnConnector.ID),
				),
			},
		},
	})
}

func TestAccConnector_tunnel(t *testing.T) {
	var bnnConnector satellite.SatelliteTunnelConfig

	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckConnectorDestroy(t, "banyan_connector.example"),
		Steps: []resource.TestStep{
			// Creates the connector with the given terraform configuration and asserts that the connector is created
			{
				Config: fmt.Sprintf(`
					resource "banyan_api_key" "example" {
						name              = "%s"
						description       = "realdescription"
						scope             = "satellite"
					}
					
					resource "banyan_connector" "example" {
						name           = "%s"
						api_key_id     = resource.banyan_api_key.example.id
						cidrs          = ["10.5.0.1/24"]
						domains        = ["example.com"]
					}
					`, rName, rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingConnector("banyan_connector.example", &bnnConnector),
					resource.TestCheckResourceAttr("banyan_connector.example", "name", rName),
					resource.TestCheckResourceAttrPtr("banyan_connector.example", "id", &bnnConnector.ID),
				),
			},
		},
	})
}

// Checks that the resource with the name resourceName exists and returns the connector object from the Banyan API
func testAccCheckExistingConnector(resourceName string, bnnConnector *satellite.SatelliteTunnelConfig) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found in state %q", rs)
		}
		resp, err := testAccClient.Satellite.Get(rs.Primary.ID)
		if err != nil {
			return err
		}
		if resp.ID != rs.Primary.ID {
			return fmt.Errorf("expected resource id %q got %q instead", resp.ID, rs.Primary.ID)
		}
		*bnnConnector = resp
		return nil
	}
}

// Uses the API to check that the connector was destroyed
func testAccCheckConnectorDestroy(t *testing.T, resourceName string) resource.TestCheckFunc {
	emptyConnector := satellite.SatelliteTunnelConfig{}
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found in state %q", rs)
		}
		r, _ := testAccClient.Satellite.Get(rs.Primary.ID)
		assert.Equal(t, r, emptyConnector)
		return nil
	}
}

// Create a connector using terraform code and only the required parameters
func testAccConnector_basic_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_api_key" "example" {
  name              = "%s"
  description       = "realdescription"
  scope             = "satellite"
}

resource "banyan_connector" "example" {
  name              = "%s"
  api_key_id 		= resource.banyan_api_key.example.id
}
`, name, name)
}
