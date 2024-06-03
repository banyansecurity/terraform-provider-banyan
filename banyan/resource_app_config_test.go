package banyan

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

var existingResourceID string

func TestAccAppConfig_update(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			fmt.Println("Executing PreConfig...")
			existingResourceID = testAccCheckBanyanConfig()
		},
		Providers:    testAccProviders,
		CheckDestroy: nil,
		Steps: []resource.TestStep{
			{
				PreConfig: func() {
					fmt.Println("Executing PreConfig...")
					existingResourceID = testAccCheckBanyanConfig()
				},
				Config: testAccAppConfig_conditionalCreate(existingResourceID),
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
					fmt.Println("ImportStateIdFunc called")
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

func testAccCheckBanyanConfig() string {
	fmt.Println("Executing function...")
	client := NewAccClient()

	present, err := client.AppConfig.Get("random")
	if err != nil {
		fmt.Println("Error checking nrpt_config presence: ", err)
		return ""
	}

	return present.Data.ID
}

func testAccCheckBanyanConfigExists(resourceName string, existingResourceID *string) error {
	cmd := exec.Command("terraform", "state", "pull")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("error running terraform state pull: %v", err)
	}

	var state terraform.State
	if err := json.Unmarshal(output, &state); err != nil {
		return fmt.Errorf("error unmarshalling state: %v", err)
	}

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
