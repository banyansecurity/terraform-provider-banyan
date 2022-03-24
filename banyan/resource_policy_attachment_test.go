package banyan

import (
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/policyattachment"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/assert"
	"testing"
)

// Use the terraform plugin sdk testing framework for acceptance testing policyattachment lifecycle
func TestAccPolicyAttachment_lifecycle(t *testing.T) {

	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyAttachment_lifecycle_create(rName),
			},
			{
				Config: testAccPolicyAttachment_lifecycle_attach_multiple(rName),
			},
			{
				Config: testAccPolicyAttachment_lifecycle_detach(rName),
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
		resp, _, err := testAccClient.PolicyAttachment.Get(rs.Primary.Attributes["attached_to_id"], rs.Primary.Attributes["attached_to_type"])
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
		r, _, err := testAccClient.PolicyAttachment.Get(policyAttachment.AttachedToID, policyAttachment.AttachedToType)
		assert.Equal(t, r, emptyPolicyAttachment)
		return err
	}
}

func testAccPolicyAttachment_lifecycle_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service" "example" {
  name = %q
  cluster = "us-west1"
  description = "some description"
  frontend {
    port = 443
  }
  site_name = "us-west1"
  backend {
    target {
      port = 443
    }
  }
  metadatatags {
    template            = "TCP_USER"
    user_facing         = true
    protocol            = "tcp"
    domain              = "%s.corp.com"
    port                = 8443
    service_app_type    = "GENERIC"
    banyan_proxy_mode   = "TCP"
    app_listen_port     = 8443
    allow_user_override = true
  }
}

resource "banyan_policy" "high-trust-any" {
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
  policy_id        = banyan_policy.high-trust-any.id
  attached_to_type = "service"
  attached_to_id   = banyan_service.example.id
  is_enforcing     = true
}
`, name, name, name, name)
}

func testAccPolicyAttachment_lifecycle_attach_multiple(name string) string {
	return fmt.Sprintf(`
resource "banyan_service" "example" {
  name = %q
  description = "some description"
  cluster = "us-west1"
  frontend {
    port = 443
  }
  site_name = "us-west1"
  backend {
    target {
      port = 443
    }
  }
  metadatatags {
    template            = "TCP_USER"
    user_facing         = true
    protocol            = "tcp"
    domain              = "%s.corp.com"
    port                = 8443
    service_app_type    = "GENERIC"
    banyan_proxy_mode   = "TCP"
    app_listen_port     = 8443
    allow_user_override = true
  }
}

resource "banyan_service" "example-two" {
  name = "%s-two"
  description = "some description"
  cluster = "us-west1"
  frontend {
    port = 80
  }
  site_name = "us-west1"
  backend {
    target {
      port = 80
    }
  }
  metadatatags {
    template            = "TCP_USER"
    user_facing         = true
    protocol            = "tcp"
    domain              = "%s.corp.com"
    port                = 8443
    service_app_type    = "GENERIC"
    banyan_proxy_mode   = "TCP"
    app_listen_port     = 8443
    allow_user_override = true
  }
}

resource "banyan_policy" "high-trust-any" {
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
  policy_id        = banyan_policy.high-trust-any.id
  attached_to_type = "service"
  attached_to_id   = banyan_service.example.id
  is_enforcing     = true
}

resource "banyan_policy_attachment" "example-two" {
  policy_id        = banyan_policy.high-trust-any.id
  attached_to_type = "service"
  attached_to_id   = banyan_service.example-two.id
  is_enforcing     = true
}
`, name, name, name, name, name, name)
}

func testAccPolicyAttachment_lifecycle_detach(name string) string {
	return fmt.Sprintf(`
resource "banyan_service" "example" {
  name = %q
  description = "some description"
  cluster = "us-west1"
  frontend {
    port = 443
  }
  site_name = "us-west1"
  backend {
    target {
      port = 443
    }
  }
  metadatatags {
    template            = "TCP_USER"
    user_facing         = true
    protocol            = "tcp"
    domain              = "%s.corp.com"
    port                = 8443
    service_app_type    = "GENERIC"
    banyan_proxy_mode   = "TCP"
    app_listen_port     = 8443
    allow_user_override = true
  }
}

resource "banyan_policy" "high-trust-any" {
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

`, name, name, name, name)
}
