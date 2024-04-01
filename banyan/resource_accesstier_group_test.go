package banyan

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccAccessTierGroup_basic(t *testing.T) {

	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: nil,
		Steps: []resource.TestStep{
			// Creates the access_tier_group with the given terraform configuration and asserts that the access_tier_group is created
			{
				Config: testAccAccessTierGroup_basic_create(rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("banyan_accesstier_group.example", "name", rName),
				),
			},
		},
	})
}

func testAccAccessTierGroup_basic_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_accesstier_group" "example" {
	name                   = "%s"
	description            = "testing-1"
	cluster                = "cluster1"
	dns_search_domains     = ""
    statsd_address 		   = "192.168.0.1:8090"
	domains                = ["test-1.com"]
	cidrs                  = ["198.169.0.1/24"]
	dns_enabled            = false
	shared_fqdn            = "testing.com"
	udp_port_number        = 16580
	keepalive              = 30
}
`, name)
}
