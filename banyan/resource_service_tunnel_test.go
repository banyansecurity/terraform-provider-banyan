package banyan

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"testing"
)

// Use the terraform plugin sdk testing framework for example testing servicetunnel lifecycle
func TestAccServiceTunnel_basic(t *testing.T) {

	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: nil,
		Steps: []resource.TestStep{
			// Creates the servicetunnel with the given terraform configuration and asserts that the servicetunnel is created
			{
				Config: fmt.Sprintf(`
					resource banyan_accesstier "example" {
						name = "%s"
						address = "*.example.com"
						api_key_id = "%s"
					}

					resource "banyan_policy_infra" "example" {
						name        = "%s"
						description = "some infrastructure policy description"
						access {
							roles       = ["ANY"]
							trust_level = "High"
						}
					}

					resource "banyan_service_tunnel" "example" {
						name              = "%s"
						description       = "realdescription"
						access_tier       = banyan_accesstier.example.name
                        policy            = banyan_policy_infra.example.id
					}
					`, rName, rName, rName, rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("banyan_service_tunnel.example", "name", rName),
				),
			},
			{
				Config: fmt.Sprintf(`
					resource banyan_accesstier "example" {
						name = "%s"
						address = "*.example.com"
						api_key_id = "%s"
						tunnel_cidrs = ["10.0.0.1/24"]
					}

					resource "banyan_policy_infra" "example" {
						name        = "%s"
						description = "some infrastructure policy description"
						access {
							roles       = ["ANY"]
							trust_level = "High"
						}
					}

					resource "banyan_service_tunnel" "example" {
						name              = "%s"
						description       = "realdescription update"
						access_tier       = banyan_accesstier.example.name
                        policy            = banyan_policy_infra.example.id
					}
					`, rName, rName, rName, rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("banyan_service_tunnel.example", "name", rName),
				),
			},
		},
	})
}
