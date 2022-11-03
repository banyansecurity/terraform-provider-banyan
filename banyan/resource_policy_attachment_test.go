package banyan

import (
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/policyattachment"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/assert"
	"testing"
)

//// Use the terraform plugin sdk testing framework for acceptance testing policyattachment lifecycle
//func TestAccPolicyAttachment_lifecycle(t *testing.T) {
//
//	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
//
//	resource.Test(t, resource.TestCase{
//		Providers: testAccProviders,
//		Steps: []resource.TestStep{
//			{
//				Config: testAccPolicyAttachment_lifecycle_create(rName),
//			},
//			{
//				Config: testAccPolicyAttachment_lifecycle_attach_multiple(rName),
//			},
//			{
//				Config: testAccPolicyAttachment_lifecycle_detach(rName),
//			},
//		},
//	})
//}

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

// Asserts using the API that the groups for the policyattachment were updated
func testAccCheckPolicyAttachmentUpdated(t *testing.T, bnnPolicyAttachment *policyattachment.GetBody, resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found %q", rs)
		}

		if bnnPolicyAttachment.AttachedToID != rs.Primary.Attributes["attached_to_id"] {
			return fmt.Errorf("incorrect attachment_id, expected %s, got: %s", bnnPolicyAttachment.AttachedToID, rs.Primary.Attributes["attached_to_id"])
		}
		return nil
	}
}

// Uses the API to check that the policyattachment was destroyed
func testAccCheckPolicyAttachmentDestroy(t *testing.T, policyAttachment *policyattachment.GetBody) resource.TestCheckFunc {
	emptyPolicyAttachment := policyattachment.GetBody{}
	return func(s *terraform.State) error {
		r, err := testAccClient.PolicyAttachment.Get(policyAttachment.AttachedToID, policyAttachment.AttachedToType)
		assert.Equal(t, r, emptyPolicyAttachment)
		return err
	}
}

func testAccPolicyAttachment_lifecycle_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service_infra_tcp" "acctest-policy-attachment-lifecycle" {
  name        = "%s"
  description = "some tcp service description"
  cluster     = "us-west"
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

resource "banyan_policy_attachment" "acctest-policy-attachment-lifecycle" {
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
  cluster     = "us-west"
  access_tier   = "us-west1"
  domain =  "%s.corp.com"
  backend_domain = "%s.internal"
  backend_port = 4321
}

resource "banyan_service_infra_tcp" "acctest-policy-attachment-lifecycle-two" {
  name        = "%s-two"
  description = "some tcp service description"
  cluster     = "us-west"
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
  cluster     = "us-west"
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
