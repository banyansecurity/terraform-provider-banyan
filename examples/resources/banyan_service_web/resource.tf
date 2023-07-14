resource "banyan_service_web" "example-web" {
  name           = "example-web"
  access_tier    = "us-west1"
  domain         = "example-web.us-west1.mycompany.com"
  backend_domain = "example-web.internal"
  backend_port   = 8443
  policy         = banyan_policy_web.example.id
}

resource "banyan_service_web" "example-service" {
  name        = "example-service"
  access_tier    = "us-west1"
  description = "Example service description"
  domain         = "example-web.us-west1.mycompany.com"
  backend_domain = "example-web.internal"
  backend_port   = 8443
  policy         = banyan_policy_web.example.id

  port        = 443
  backend_port = 443
  backend_tls = true
  backend_tls_insecure = false

  # Optional Fields
  suppress_device_trust_verification = false
  description_link = "https://example.com"
  access_tier      = "access-tier-1"
  policy           = "policy-id-123"
  available_in_app = true
  icon             = "example-icon"
  disable_private_dns = false

  custom_http_headers = {
    "X-Auth-Token" = "abc123"
    "X-Forwarded-For" = "192.168.1.1"
  }

  dns_overrides = {
    "internal.myservice.com" = "10.23.0.1"
    "exposed.service.com" = "internal.myservice.com"
  }

  whitelist = ["backend-workload-instance1", "backend-workload-instance2"]

  custom_trust_cookie {
    same_site_policy = "lax"
    trust_cookie_path = "/path"
  }

  service_account_access {
    authorization_header = true
    query_parameter      = "token"
    custom_header        = "Authorization"
  }

  custom_tls_cert {
    key_file  = "private-key.pem"
    cert_file = "certificate.pem"
  }

  exemptions {
    legacy_paths        = ["/legacy1", "/legacy2"]
    paths               = ["/path1", "/path2"]
    origin_header       = ["https://myorigin.com:443"]
    source_cidrs        = ["192.168.0.0/24", "10.0.0.0/16"]
    mandatory_headers   = ["X-Http-Banyan", "Allow"]
    http_methods        = ["GET", "POST"]
    target_domain       = ["https://example.com:443"]
  }
}
