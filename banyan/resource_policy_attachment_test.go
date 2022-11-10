package banyan

import (
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/policyattachment"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"testing"
)

// Use the terraform plugin sdk testing framework for acceptance testing policyattachment lifecycle
// This resource is depreciated and used with the depreciated sevice schemas. this tests the depreciated lifecycle
// and will be removed in the future
func TestAccPolicyAttachment_lifecycle(t *testing.T) {

	var policyAttachment policyattachment.GetBody

	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	resource.Test(t, resource.TestCase{
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyAttachment_lifecycle_create(rName),
				Check:  testAccCheckExistingPolicyAttachment("banyan_policy_attachment.example", &policyAttachment),
			},
		},
	})
}

// Checks that the resource with the name resourceName exists and returns the policyattachment object from the Banyan API
func testAccCheckExistingPolicyAttachment(resourceName string, policyAttachment *policyattachment.GetBody) resource.TestCheckFunc {
	return func(s *terraform.State) error {

		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found %q", rs)
		}
		resp, err := testAccClient.PolicyAttachment.Get(rs.Primary.Attributes["attached_to_id"], rs.Primary.Attributes["attached_to_type"])
		if err != nil {
			return err
		}
		if resp.PolicyID != rs.Primary.Attributes["policy_id"] {
			return fmt.Errorf("expected resource id %q got %q instead", resp.PolicyID, rs.Primary.ID)
		}
		*policyAttachment = resp
		return nil
	}
}

func testAccPolicyAttachment_lifecycle_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service_infra_tcp" "acctest-policy-attachment-lifecycle" {
  name        = "%s"
  description = "some tcp service description"
  cluster     = "cluster1"
  access_tier   = "us-west1"
  domain =  "%s.corp.com"
  backend_domain = "%s.internal"
  backend_port = 4321
}

resource "banyan_policy_infra" "high-trust-any" {
  name        = %q
  description = "Allows any user with a high trust score"
  access {
    roles                             = [banyan_role.everyone.name]
    trust_level                       = "High"
  }
}

resource "banyan_role" "everyone" {
  name = %q
  description = "all users"
  user_group = ["Everyone"]
}

resource "banyan_policy_attachment" "example" {
  policy_id        = banyan_policy_infra.high-trust-any.id
  attached_to_type = "service"
  attached_to_id   = banyan_service_infra_tcp.acctest-policy-attachment-lifecycle.id
}
`, name, name, name, name, name)
}

func testAccPolicyAttachment_lifecycle_attach_multiple(name string) string {
	return fmt.Sprintf(`
resource "banyan_service_infra_tcp" "acctest-policy-attachment-lifecycle" {
  name        = "%s"
  description = "some tcp service description"
  cluster     = "cluster1"
  access_tier   = "us-west1"
  domain =  "%s.corp.com"
  backend_domain = "%s.internal"
  backend_port = 4321
}

resource "banyan_service_infra_tcp" "acctest-policy-attachment-lifecycle-two" {
  name        = "%s-two"
  description = "some tcp service description"
  cluster     = "cluster1"
  access_tier   = "us-west1"
  domain =  "%s-two.corp.com"
  backend_domain = "%s-two.internal"
  backend_port = 4321
}

resource "banyan_policy_infra" "high-trust-any" {
  name        = %q
  description = "Allows any user with a high trust score"
  access {
    roles                             = [banyan_role.everyone.name]
    trust_level                       = "High"
  }
}

resource "banyan_role" "everyone" {
  name = %q
  description = "all users"
  user_group = ["Everyone"]
}

resource "banyan_policy_attachment" "acctest-policy-attachment-lifecycle" {
  policy_id        = banyan_policy_infra.high-trust-any.id
  attached_to_type = "service"
  attached_to_id   = banyan_service_infra_tcp.acctest-policy-attachment-lifecycle.id
  is_enforcing     = true
}

resource "banyan_policy_attachment" "acctest-policy-attachment-lifecycle-two" {
  policy_id        = banyan_policy_infra.high-trust-any.id
  attached_to_type = "service"
  attached_to_id   = banyan_service_infra_tcp.acctest-policy-attachment-lifecycle-two.id
  is_enforcing     = true
}
`, name, name, name, name, name, name, name, name)
}

func testAccPolicyAttachment_lifecycle_detach(name string) string {
	return fmt.Sprintf(`
resource "banyan_service_infra_tcp" "acctest-policy-attachment-lifecycle" {
  name        = "%s"
  description = "some tcp service description"
  cluster     = "cluster1"
  access_tier   = "us-west1"
  domain =  "%s.corp.com"
  backend_domain = "%s.internal"
  backend_port = 4321
}

resource "banyan_policy_infra" "high-trust-any" {
  name        = %q
  description = "Allows any user with a high trust score"
  access {
    roles                             = [banyan_role.everyone.name]
    trust_level                       = "High"
  }
}

resource "banyan_role" "everyone" {
  name = %q
  description = "all users"
  user_group = ["Everyone"]
}

`, name, name, name, name, name)
}
