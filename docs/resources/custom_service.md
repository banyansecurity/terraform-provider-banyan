# Custom Service

### Example
```hcl
resource "banyan_custom_service" "acctest-custom" {
  cluster      = "dev05-banyan"
  access_tiers = ["us-west1"]
  name         = "custom-service"
  description  = "acceptance test service"
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
    http_connect   = true
    whitelist      = ["allowme.com", "newurl.org"]

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

  tls_sni = ["custom-service"]

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
      enabled                            = true
      service_domain_name                = "custom-service"
      post_auth_redirect_path            = "/some/path"
      api_path                           = "/api"
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
      query_param          = "somequeryparam"
      authorization_header = true
      custom_header        = "customheaderhere"
    }
  }
}
```