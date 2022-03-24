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
func TestAccService_basic_web(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckService_destroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			// Create the service using terraform config and check that it exists
			{
				Config: testAccService_basic_web_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service.acctest-web", &bnnService),
				),
			},
		},
	})
}

func TestAccService_ssh(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckService_destroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			{
				Config: testAccService_ssh_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service.acctest-ssh", &bnnService),
				),
			},
		},
	})
}

func TestAccService_rdp(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckService_destroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			{
				Config: testAccService_rdp_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service.acctest-rdp", &bnnService),
				),
			},
		},
	})
}

func TestAccService_database(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckService_destroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			{
				Config: testAccService_database_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service.acctest-database", &bnnService),
				),
			},
		},
	})
}

func TestAccService_k8s(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckService_destroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			{
				Config: testAccService_k8s_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service.acctest-k8s", &bnnService),
				),
			},
		},
	})
}

func TestAccService_tcp(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckService_destroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			{
				Config: testAccService_tcp_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service.acctest-tcp", &bnnService),
				),
			},
		},
	})
}

func TestAccService_complex(t *testing.T) {
	var bnnService service.GetServiceSpec
	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckService_destroy(t, &bnnService.ServiceID),
		Steps: []resource.TestStep{
			// Create the service using terraform config and check that it exists
			{
				Config: testAccService_complex_create(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service.acctest-complex", &bnnService),
					resource.TestCheckResourceAttr("banyan_service.acctest-complex", "name", rName),
					resource.TestCheckResourceAttrPtr("banyan_service.acctest-complex", "id", &bnnService.ServiceID),
				),
			},
			// Update the resource with terraform and ensure it was correctly updated
			{
				Config: testAccService_complex_update(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckExistingService("banyan_service.acctest-complex", &bnnService),
					testAccCheckServiceConnectorNameUpdated(&bnnService, "some-new-connector-name"),
					resource.TestCheckResourceAttrPtr("banyan_service.acctest-complex", "id", &bnnService.ServiceID),
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

// Returns terraform configuration for a typical basic service
func testAccService_basic_web_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service" "acctest-web" {
  name        = "%s"
  description = "some web service description"
  cluster     = "us-west"
  site_name   = "us-west1"
  frontend {
    port = 443
  }
  backend {
    target {
      name = "%s.internal"
      port = 8443
    }
  }
  cert_settings {
    dns_names = ["%s.corp.com"]
  }
  metadatatags {
    template            = "WEB_USER"
    user_facing         = true
    protocol            = "https"
    domain              = "%s.corp.com"
    port                = 443
    service_app_type    = "WEB"
  }
}
`, name, name, name, name)
}

// Returns terraform configuration for a typical ssh service
func testAccService_ssh_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service" "acctest-ssh" {
  name        = "%s"
  description = "some ssh service"
  cluster     = "us-west"
  site_name = "us-west1"
  tls_sni     = ["%s.mattorg.bnntest.com"]
  frontend {
    port = 8443
  }
  backend {
    target {
      name               = "%s.internal"
      port               = 22
      tls                = false
      tls_insecure       = false
      client_certificate = false
    }
  }
  cert_settings {
    dns_names = ["%s.mattorg.bnntest.com"]
  }
  metadatatags {
    template           = "TCP_USER"
    user_facing        = true
    protocol           = "tcp"
    domain             = "%s.mattorg.bnntest.com"
    port               = 8443
    service_app_type   = "SSH"
    ssh_service_type   = "TRUSTCERT"
    write_ssh_config   = true
    ssh_chain_mode     = false
    ssh_host_directive = "%s.mattorg.bnntest.com"
  }
}
`, name, name, name, name, name, name)
}

// Returns terraform configuration for a typical rdp service
func testAccService_rdp_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service" "acctest-rdp" {
  name        = "%s"
  description = "some rdp service description"
  cluster     = "us-west"
  site_name   = "us-west1"
  tls_sni     = ["%s.corp.com"]
  frontend {
    port = 8443
  }
  backend {
    target {
      name = "%s.internal"
      port = 3389
    }
  }
  cert_settings {
    dns_names = ["%s.corp.com"]
  }
  metadatatags {
    template            = "TCP_USER"
    user_facing         = true
    protocol            = "tcp"
    domain              = "service.domainname"
    port                = 8443
    service_app_type    = "RDP"
    banyan_proxy_mode   = "TCP"
    app_listen_port     = 3389
    
  }
}
`, name, name, name, name)
}

// Returns terraform configuration for a typical database service
func testAccService_database_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service" "acctest-database" {
  name        = "%s"
  description = "some database service description"
  cluster     = "us-west"
  site_name   = "us-west1"
  tls_sni     = ["%s.corp.com"]
  frontend {
    port = 845
  }
  backend {
    target {
      name = "%s.internal"
      port = 8845
    }
  }
  cert_settings {
    dns_names = ["%s.corp.com"]
  }
  metadatatags {
    template            = "TCP_USER"
    user_facing         = true
    protocol            = "tcp"
    domain              = "%s.corp.com"
    port                = 845
    service_app_type    = "DATABASE"
    banyan_proxy_mode   = "TCP"
    app_listen_port     = 8845
  }
}
`, name, name, name, name, name)
}

// Returns terraform configuration for a typical k8s service
func testAccService_k8s_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service" "acctest-k8s" {
  name        = "%s"
  description = "some k8s service description"
  cluster     = "us-west"
  site_name = "us-west1"
  tls_sni     = ["%s.corp.com"]
  frontend {
    port = 8443
  }
  backend {
    target {
      name = "%s.internal"
      port = 3389
    }
  }
  cert_settings {
    dns_names = ["%s.corp.com"]
  }
  metadatatags {
    template            = "TCP_USER"
    user_facing         = true
    protocol            = "tcp"
    domain              = "%s.corp.com"
    port                = 8443
    service_app_type    = "K8S"
    banyan_proxy_mode   = "CHAIN"
    app_listen_port     = 8443
    kube_cluster_name = "k8s-cluster"
    kube_ca_key = "k8scAk3yH3re"
  }
}
`, name, name, name, name, name)
}

// Returns terraform configuration for a typical k8s service
func testAccService_tcp_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service" "acctest-tcp" {
  name        = "%s"
  description = "some tcp service description"
  cluster     = "us-west"
  site_name = "us-west1"
  tls_sni     = ["%s.corp.com"]
  frontend {
    port = 8443
  }
  backend {
    target {
      name = "%s.internal"
      port = 3389
    }
  }
  cert_settings {
    dns_names = ["%s.corp.com"]
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
  }
}
`, name, name, name, name, name)
}

// service with every option possible
func testAccService_complex_create(name string) string {
	return fmt.Sprintf(`
resource "banyan_service" "acctest-complex" {
  cluster     = "dev05-banyan"
  site_name = "us-west1"
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
    cidr_address {
      cidr  = "10.0.1.0/24"
      ports = "888"
    }
  }

  backend {
    allow_patterns {
      hostnames = ["differentone.com", "foo.bar.baz"]
      cidrs     = ["10.0.1.0/24"]
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

  frontend {
    cidr = "127.44.111.14/32"
    port = 1112
  }

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
func testAccService_complex_update(name string) string {
	return fmt.Sprintf(`
resource "banyan_service" "acctest-complex" {
  cluster     = "dev05-banyan"
  site_name = "us-west1"
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
    cidr_address {
      cidr  = "10.0.1.0/24"
      ports = "888"
    }
  }

  backend {
    allow_patterns {
      hostnames = ["differentone.com", "foo.bar.baz"]
      cidrs     = ["10.0.1.0/24"]
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

  frontend {
    cidr = "127.44.111.14/32"
    port = 1112
  }

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
