package banyan

import (
	"fmt"
	"log"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

var existingID string

// Use the terraform plugin sdk testing framework for example testing apikey lifecycle
// func TestAccAppConfig_basic(t *testing.T) {
// 	resource.Test(t, resource.TestCase{
// 		PreCheck: func() {
// 			testAccCheckBanyanConfigDestroy(t)
// 		},
// 		Providers:    testAccProviders,
// 		CheckDestroy: nil,
// 		Steps: []resource.TestStep{
// 			{
// 				Config: testAccAppConfig_basic_create(),
// 				Check:  resource.ComposeTestCheckFunc(),
// 			},
// 		},
// 	})
// }

func TestAccAppConfig_update(t *testing.T) {

	var existingResourceID string
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccCheckBanyanConfigExists("banyan_app_config.example", &existingResourceID)
		},
		Providers:    testAccProviders,
		CheckDestroy: nil,
		Steps: []resource.TestStep{
			{
				// PreConfig: func() {
				// 	existingResourceID, err := checkExistingResourceID()
				// 	if err != nil {
				// 		t.Fatal(err)
				// 	}
				// 	if existingResourceID != "" {
				// 		t.Skip("Resource already exists, skipping creation step")
				// 	}
				// },
				// PreConfig: func() { testAccCheckBanyanConfigDestroy(t) },
				Config:    testAccAppConfig_conditionalCreate(existingResourceID),
				Check: resource.ComposeAggregateTestCheckFunc(
					func(s *terraform.State) error {
						if existingResourceID == "" {
							rs, ok := s.RootModule().Resources["banyan_app_config.example"]
							if !ok {
								return fmt.Errorf("Not found: %s", "banyan_app_config.example")
							}
							if rs.Primary.ID == "" {
								return fmt.Errorf("No ID is set")
							}
							existingResourceID = rs.Primary.ID
						}
						return nil
					},
				),
			},
			{
				ResourceName:      "banyan_app_config.example",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: func(*terraform.State) (string, error) {
					return existingResourceID, nil
				},
			},
			{
				Config: testAccAppConfig_basic_update(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("banyan_app_config.example", "nrpt_config", "false"),
				),
			},
		},
	})
}

func testAccAppConfig_basic_create() string {
	return fmt.Sprintf(`
resource "banyan_app_config" "example" {
  nrpt_config = true
}
`)
}

func testAccAppConfig_basic_update() string {
	return fmt.Sprintf(`
resource "banyan_app_config" "example" {
  nrpt_config = false
}
`)
}

func testAccAppConfig_conditionalCreate(existingResourceID string) string {
	if existingResourceID == "" {
		return testAccAppConfig_basic_create()
	}
	return ``
}

func testAccPreCheckResourceExists(resourceName string, existingResourceID *string) error {
	state := terraform.NewState()
	rs, ok := state.RootModule().Resources[resourceName]
	if !ok {
		// Resource not found in state
		return nil
	}

	if rs.Primary.ID != "" {
		*existingResourceID = rs.Primary.ID
	}
	return nil
}

// func checkExistingResourceID(provider *schema.Provider) (string, error) {
// 	// Read the Terraform state using the provider
// 	state := provider.Meta().(*ProviderMeta).RawState

// 	// Get the resource instance
// 	rs, ok := state.RootModule().Resources["banyan_app_config.example"]
// 	if !ok {
// 		return "", fmt.Errorf("Resource not found: banyan_app_config.example")
// 	}

// 	// Check if the resource has an ID
// 	if rs.Primary.ID == "" {
// 		return "", fmt.Errorf("No ID is set for the resource: banyan_app_config.example")
// 	}

// 	return rs.Primary.ID, nil
// }

func testAccCheckBanyanConfig() string {
	client := NewAccClient()

	present, err := client.AppConfig.Get("sad")
	if err != nil {
		return ""
	}

	log.Fatalf("ID %s", present.Data.ID)
	return present.Data.ID
}
func testAccCheckBanyanConfigExists(resourceName string, existingID *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("Not found: %s", resourceName)
		}

		if rs.Primary.ID != "" {
			*existingID = rs.Primary.ID
		}

		return nil
	}
}

func testAccCheckBanyanConfigDestroy(t *testing.T) error {
	client := NewAccClient()

	present, err := client.AppConfig.Get("sad")
	if err != nil {
		return fmt.Errorf("Error checking nrpt_config presence: %s", err)
	}

	if present.Data.ID != "" {
		t.Skip("skipping")
	}

	return nil
}
