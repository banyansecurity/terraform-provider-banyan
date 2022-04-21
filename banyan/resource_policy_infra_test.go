package banyan

import (
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/policy"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"testing"
)

func TestAccPolicy_infrastructure(t *testing.T) {
	var bnnPolicy policy.GetPolicy

	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckPolicy_destroy(t, &bnnPolicy.ID),
		Steps: []resource.TestStep{
			// Create the policy using terraform config and check that it exists
			{
				Config: testAccPolicy_infrastructure_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingPolicy("banyan_policy_infra.example", &bnnPolicy),
				),
			},
		},
	})
}

// Returns terraform configuration for the policy
func testAccPolicy_infrastructure_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_policy_infra" "example" {
  name        = "%s"
  description = "some infrastructure policy description"
  access {
    roles       = ["ANY"]
    trust_level = "High"
  }
}
`, name)
}
