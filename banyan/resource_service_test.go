package banyan

import (
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Use the terraform plugin sdk testing framework for acceptance testing banyan service lifecycle
func TestAccService_basic(t *testing.T) {
	var bnnService service.GetServiceSpec

	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckService_destroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			// Create the service using terraform config and check that it exists
			{
				Config: testAccService_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service.acceptance", &bnnService),
					resource.TestCheckResourceAttr("banyan_service.acceptance", "name", rName),
					resource.TestCheckResourceAttrPtr("banyan_service.acceptance", "id", &bnnService.ServiceID),
				),
			},
			// Update the resource with terraform and ensure it was correctly updated
			{
				Config: testAccService_update(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service.acceptance", &bnnService),
					testAccCheckServiceConnectorNameUpdated(&bnnService, "some-new-connector-name"),
					resource.TestCheckResourceAttrPtr("banyan_service.acceptance", "id", &bnnService.ServiceID),
				),
			},
		},
	})
}

// Checks that the resource with the name resourceName exists and returns the role object from the Banyan API
func testAccCheckExistingService(resourceName string, bnnService *service.GetServiceSpec) resource.TestCheckFunc {
	return func(s *terraform.State) error {

		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found %q", rs)
		}
		resp, _, err := testAccClient.Service.Get(rs.Primary.ID)
		if err != nil {
			return err
		}
		if resp.ServiceID != rs.Primary.ID {
			return fmt.Errorf("expected resource id %q got %q instead", resp.ServiceID, rs.Primary.ID)
		}
		*bnnService = resp
		return nil
	}
}

// Asserts using the API that the Spec.Backend.ConnectorName for the service was updated
func testAccCheckServiceConnectorNameUpdated(bnnService *service.GetServiceSpec, connectorName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if connectorName != bnnService.CreateServiceSpec.Spec.Backend.ConnectorName {
			return fmt.Errorf("incorrect connector_name, expected %s, got: %s", connectorName, bnnService.CreateServiceSpec.Spec.Backend.ConnectorName)
		}
		return nil
	}
}

// Uses the API to check that the service was destroyed
func testAccCheckService_destroy(t *testing.T, id *string) resource.TestCheckFunc {
	emptyService := service.GetServiceSpec{}
	return func(s *terraform.State) error {
		r, _, err := testAccClient.Service.Get(*id)
		assert.Equal(t, r, emptyService)
		return err
	}
}

// Returns terraform configuration for the service
func testAccService_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service" "acceptance" {
  cluster     = "dev05-banyan"
  name        = %q
  description = "acceptance test service"
  metadatatags {
    domain           = "test2v.com"
    port             = 1111
    protocol         = "https"
    service_app_type = "WEB"
    user_facing      = false
    template         = "WEB_USER"
    app_listen_port  = 9191
    include_domains  = ["test2v.com"]
  }

  client_cidrs {
    clusters = ["cluster"]
    address {
      cidr  = "127.127.127.1/32"
      ports = "888"
    }
    host_tag_selector = [
      { testkey = "testvalue" },
      { testkey2 = "testvalue2" }
    ]
  }

  backend {
    allow_patterns {
      hostnames = ["differentone.com", "foo.bar.baz"]
      cidrs     = ["55.55.55.55/5"]
      ports {
        port_list = [88, 99]
        port_range {
          min = 8
          max = 9
        }
      }
    }

    dns_overrides = {
      "internal.mysvc.com" = "10.23.0.1"
      "exposed.service.com" : "internal.myservice.com"
    }

    connector_name = "hahah-connector-name"
    http_connect = true
    whitelist = ["allowme.com", "newurl.org"]

    target {
      client_certificate = true
      name               = "targetbacknd"
      port               = 1515
      tls                = true
      tls_insecure       = true
    }
  }

  frontend_address {
    cidr = "127.44.111.14/32"
    port = 1112
  }

  host_tag_selector = [
    { site_name = "sitename" }
  ]

  tls_sni = [%q]

  cert_settings {
    letsencrypt = false
    dns_names   = ["hello_dns_name", "dns_name2"]
    custom_tls_cert {
      enabled   = false
      cert_file = "asdf"
      key_file  = "asdf"
    }
  }

  http_settings {
    enabled = true
    oidc_settings {
      enabled = true
      service_domain_name = %q
      post_auth_redirect_path = "/some/path"
      api_path = "/api"
      suppress_device_trust_verification = false
      trust_callbacks = {
        "somecallback" : "ohhey"
      }
    }
    http_health_check {
      enabled      = true
      addresses    = ["88.99.101.2"]
      method       = "GET"
      path         = "/path"
      user_agent   = "chrome"
      from_address = ["11.11.11.99"]
      https        = true
    }
    exempted_paths {
      enabled = true
      patterns {
        template          = "USER"
        source_cidrs      = ["10.0.0.1/24"]
        methods           = ["GET", "POST"]
        paths             = ["/path1", "/path2"]
        mandatory_headers = ["someheader", "other_header"]
      }
    }
    headers = {
      "foo" = "bar"
    }
    token_loc {
      query_param = "somequeryparam"
      authorization_header = true
      custom_header = "customheaderhere"
    }
  }
}
`, name, name, name)
}

// Returns updated terraform configuration for the service
func testAccService_update(name string) string {
	return fmt.Sprintf(`
resource "banyan_service" "acceptance" {
  cluster     = "dev05-banyan"
  name        = %q
  description = "acceptance test service"
  metadatatags {
    domain           = "test2v.com"
    port             = 1111
    protocol         = "https"
    service_app_type = "WEB"
    user_facing      = false
    template         = "WEB_USER"
    app_listen_port  = 9191
    include_domains  = ["test2v.com"]
  }

  client_cidrs {
    clusters = ["cluster"]
    address {
      cidr  = "127.127.127.1/32"
      ports = "888"
    }
    host_tag_selector = [
      { testkey = "testvalue" },
      { testkey2 = "testvalue2" }
    ]
  }

  backend {
    allow_patterns {
      hostnames = ["differentone.com", "foo.bar.baz"]
      cidrs     = ["55.55.55.55/5"]
      ports {
        port_list = [88, 99]
        port_range {
          min = 8
          max = 9
        }
      }
    }

    dns_overrides = {
      "internal.mysvc.com" = "10.23.0.1"
      "exposed.service.com" : "internal.myservice.com"
    }

    connector_name = "some-new-connector-name"
    http_connect = true
    whitelist = ["allowme.com", "newurl.org"]

    target {
      client_certificate = true
      name               = "targetbacknd"
      port               = 1515
      tls                = true
      tls_insecure       = true
    }
  }

  frontend_address {
    cidr = "127.44.111.14/32"
    port = 1112
  }

  host_tag_selector = [
    { site_name = "sitename" }
  ]

  tls_sni = [%q]

  cert_settings {
    letsencrypt = false
    dns_names   = ["hello_dns_name", "dns_name2"]
    custom_tls_cert {
      enabled   = false
      cert_file = "asdf"
      key_file  = "asdf"
    }
  }

  http_settings {
    enabled = true
    oidc_settings {
      enabled = true
      service_domain_name = %q
      post_auth_redirect_path = "/some/path"
      api_path = "/api"
      suppress_device_trust_verification = false
      trust_callbacks = {
        "somecallback" : "ohhey"
      }
    }
    http_health_check {
      enabled      = true
      addresses    = ["88.99.101.2"]
      method       = "GET"
      path         = "/path"
      user_agent   = "chrome"
      from_address = ["11.11.11.99"]
      https        = true
    }
    exempted_paths {
      enabled = true
      patterns {
        template          = "USER"
        source_cidrs      = ["10.0.0.1/24"]
        methods           = ["GET", "POST"]
        paths             = ["/path1", "/path2"]
        mandatory_headers = ["someheader", "other_header"]
      }
    }
    headers = {
      "foo" = "bar"
    }
    token_loc {
      query_param = "somequeryparam"
      authorization_header = true
      custom_header = "customheaderhere"
    }
  }
}
`, name, name, name)
}

func Test_validateCIDR_tooLargeSuffixBitSize(t *testing.T) {
	t.Parallel()
	warns, errs := validateCIDR()("10.1.2.1/3666", "key")
	assert.Empty(t, warns)
	assert.NotEmpty(t, errs)
}

func Test_validateCIDR_0SuffixBitSize(t *testing.T) {
	t.Parallel()
	warns, errs := validateCIDR()("10.1.2.1/0", "key")
	assert.Empty(t, warns)
	assert.Empty(t, errs)
}

func Test_validateCIDR_validCIDR(t *testing.T) {
	t.Parallel()
	warns, errs := validateCIDR()("10.1.2.1/32", "key")
	assert.Empty(t, warns)
	assert.Empty(t, errs)
}

func Test_validateCIDR_invalidIPValues(t *testing.T) {
	t.Parallel()
	warns, errs := validateCIDR()("300.1.2.1/32", "key")
	assert.Empty(t, warns)
	assert.NotEmpty(t, errs)
}

func Test_portValidation_zeroPort(t *testing.T) {
	t.Parallel()
	warns, errs := validatePort()(0, "key")
	assert.Empty(t, warns)
	assert.Empty(t, errs)
}

func Test_portValidation_maxPortValue(t *testing.T) {
	t.Parallel()
	warns, errs := validatePort()(65535, "key")
	assert.Empty(t, warns)
	assert.Empty(t, errs)
}

func Test_portValidation_negativePortValue(t *testing.T) {
	t.Parallel()
	warns, errs := validatePort()(-1, "key")
	assert.Empty(t, warns)
	assert.NotEmpty(t, errs)
}

func Test_portValidation_tooLargePortValue(t *testing.T) {
	t.Parallel()
	warns, errs := validatePort()(65536, "key")
	assert.Empty(t, warns)
	assert.NotEmpty(t, errs)
}

func Test_templateValidation_validNonEmpty(t *testing.T) {
	t.Parallel()
	warns, errs := validateTemplate()("WEB_USER", "key")
	assert.Empty(t, warns)
	assert.Empty(t, errs)
}

func Test_templateValidation_validEmpty(t *testing.T) {
	t.Parallel()
	warns, errs := validateTemplate()("", "key")
	assert.Empty(t, warns)
	assert.Empty(t, errs)
}

func Test_templateValidation_invalidValue_returnsError(t *testing.T) {
	t.Parallel()
	warns, errs := validateTemplate()("invalid", "key")
	assert.Empty(t, warns)
	assert.NotEmpty(t, errs)
}

func Test_typeSwitchPort(t *testing.T) {
	t.Parallel()
	var val interface{}
	_, err := typeSwitchPort(val)
	if err == nil {
		t.Errorf("expected error here, got none")
	}
	val = 1234
	v, _ := typeSwitchPort(val)
	if v != val {
		t.Errorf("got %T expected %T", v, val)
	}
	sVal := "1234"
	v, _ = typeSwitchPort(sVal)
	if v != val {
		t.Errorf("got %T expected %T", v, val)
	}
}
