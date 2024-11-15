package banyan

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccRegisteredDomain_basic(t *testing.T) {

	rName := fmt.Sprintf("tf-acc-%s.bnntest.com", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: nil,
		Steps: []resource.TestStep{
			{
				Config: testAccRD_basic_create(rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("banyan_registered_domain.example", "name", rName),
				),
			},
		},
	})
}

func testAccRD_basic_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_registered_domain" "example" {
	name        = "%s"
	cluster     = "global-edge"
	cname       = "gke-usw1-at01.infra.bnntest.com"
	description = "test me new"
}
`, name)
}

func TestAccRegisteredDomain(t *testing.T) {

	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: nil,
		Steps: []resource.TestStep{
			// Creates the registered domain with the given terraform configuration and asserts that the registered is created
			{
				Config: fmt.Sprintf(`

					resource "banyan_registered_domain" "example" {
						name        = "%s"
						cluster     = "global-edge"
						cname       = "gke-usw1-at01.infra.bnntest.com"
						description = "test me ne6"
					}
					`, rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("banyan_registered_domain.example", "name", rName),
				),
			},
			{
				ResourceName:      "banyan_registered_domain.example",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: fmt.Sprintf(`

					resource "banyan_registered_domain" "example" {
						name        = "%s"
						cluster     = "cluster1"
						cname       = "gke-usw1-at01.infra.bnntest.com"
					}
					`, rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("banyan_registered_domain.example", "name", rName),
				),
			},
			{
				ResourceName:      "banyan_registered_domain.example",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}
