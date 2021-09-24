terraform {
  required_providers {
//    okta = {
//       source = "okta/okta"
//       version = "~> 3.13.0"
//    }
    banyan = {
      version = "0.1"
      source = "github.com/banyansecurity/banyan"
    }
  }
}

//provider "okta" {
//    org_name = var.okta_org_name
//    base_url = "okta.com"
//    api_token = var.okta_api_token
//}

provider "banyan" {
    refresh_token = var.banyan_refresh_token
    host = var.banyan_host
}

# data "banyan_oidc_settings" "my-urls" {}
//data "okta_everyone_group" "everyone" {}

//output "oidc_redirect_url" {
//    value = data.banyan_oidc_settings.my-urls.authorization_endpoint
//}

//resource "banyan_org_idp_config" "my-idp-config" {
//    idp_name = "OKTA"
//    idp_protocol = "OIDC"
//    idp_config {
//        issuer_url = "http://${var.okta_org_name}.okta.com"
//        client_secret = okta_app_oauth.banyan-trustprovider.client_secret
//        client_id = okta_app_oauth.banyan-trustprovider.client_id
//    }
//}

//resource "okta_app_oauth" "banyan-trustprovider" {
//    label = "terraform banyan trust provider"
//    grant_types = ["authorization_code"]
//    type = "web"
//    redirect_uris = [data.banyan_oidc_settings.my-urls.redirect_url]
//    hide_web = true
//
//    lifecycle {
//        ignore_changes = [groups]
//    }
//    // need to find way to setup groups claim currently an "internal" api could make our own provider for that...
//}

//resource "okta_app_group_assignment" "banyan-trustprovider-everyone-group" {
//    app_id = okta_app_oauth.banyan-trustprovider.id
//    group_id = data.okta_everyone_group.everyone.id
//}

//resource "banyan_service" "test-service" {
//  cluster = "dev05-banyan"
//  name = "realtftest"
//  description = "description2"
//  metadatatags {
//    domain = "test2.com"
//    port = 1111
//    protocol = "https"
//    service_app_type = "WEB"
//    user_facing = false
//    template= "WEB_USER"
//    app_listen_port = 9191
//    include_domains = ["test.com"]
//  }
//  spec {
//    client_cidrs {
//      clusters = ["cliuster1&&&"]
//      address {
//        cidr = "127.127.127.1/32"
//        ports = "888"
//      }
//      address {
//        cidr = "255.220.225.1/32"
//        ports = "111"
//      }
//      host_tag_selectors {
//        host_tag_selector ={
//            "map" = "hi"
//          }
//        }
//      host_tag_selectors {
//        host_tag_selector ={
//          "map" = "hi"
//        }
//     }
//    }
//    attributes {
//      frontend_address {
//        cidr = "127.44.111.14/32"
//        port = "1111"
//      }
//      frontend_address {
//        cidr = "127.99.114.14/32"
//        port = 0
//      }
//      host_tag_selector {
//        site_name = "sitename"
//      }
//      host_tag_selector {
//        site_name = "sites"
//      }
//      tls_sni = ["sni_new2", "tls_sni616"]
//    }
//    backend {
//      target {
//        client_certificate = true
//        name = "targetbacknd"
//        port = 1515
//        tls = true
//        tls_insecure = true
//      }
//      dns_overrides = {
//        "internal.mysvc.com" = "10.23.0.1"
//        "exposed.service.com" : "internal.myservice.com"
//      }
//      backend_allowlist = ["allowme.com", "newurl.org"]
//      http_connect = true
//      connector_name = "hahah-connector-name"
//      backend_allow_pattern {
//        hostnames = ["backendallowhostName1", "hostname.com"]
//        cidrs = ["99.99.99.99/9"]
//        ports {
//          port_list = [111,222]
//          port_range {
//            min = 1
//            max = 5
//          }
//        }
//      }
//      backend_allow_pattern {
//        hostnames = ["differentone.com", "foo.bar.baz"]
//        cidrs = ["55.55.55.55/5"]
//        ports {
//          port_list = [88,99]
//          port_range {
//            min = 8
//            max = 9
//          }
//        }
//      }
//    }
//    cert_settings {
//      letsencrypt = false
//      dns_names = ["hello_dns_name", "dns_name2"]
//      custom_tls_cert {
//        enabled = false
//        cert_file = "asdf"
//        key_file = "asdf"
//      }
//    }
//    http_settings {
//      enabled = true
//
//      http_health_check {
//        enabled = true
//        addresses = ["88.99.101.2"]
//        method = "GET"
//        path = "/path"
//        user_agent = "chrome"
//        from_address = ["11.11.11.99"]
//        https = true
//      }
//      http_redirect {
//        enabled = true
//        addresses = ["127.98.2.1"]
//        from_address = ["43.12.31.1"]
//        url = "hello.com"
//        status_code = 209
//      }
//      oidc_settings {
//        enabled = true
//        service_domain_name = "service.domain.name"
//        post_auth_redirect_path = "/new/path"
//        api_path = "/api/path"
//        suppress_device_trust_verification = true
//        trust_callbacks = {
//          "h" = "y"
//          "b" = "j"
//        }
//      }
//      headers = {
//        "header1" = "headers"
//      }
//      exempted_paths {
//        enabled = true
//        paths = ["/path1", "/path2"]
//        pattern {
//          source_cidrs = ["222.222.222.222/8"]
//          methods = ["GET"]
//          paths = ["/path9000"]
//          mandatory_headers = ["mandatory_header"]
//          hosts {
//            origin_header = [
//              "https://originheader.org:80"]
//            target = [
//              "http://target.io:70"]
//          }
//        }
//        pattern {
//          source_cidrs = ["111.111.111.111/8"]
//          methods = ["POST"]
//          paths = ["/newPath"]
//          mandatory_headers = ["other_header"]
//          hosts {
//            origin_header = [
//              "http://other_originheader.com:90"]
//            target = [
//              "http://other_target.net:8080"]
//          }
//        }
//      }
//    }
//  }
//}

resource "banyan_policy" "test-policy" {
  name = "realtfpolicytest"
  description = "realdescription"
  metadatatags {
    template = "USER"
  }
  spec {
    access {
      roles = ["ANY", "HI"]
      rules {
        conditions {
          trust_level = "High"
        }
        l7_access {
          resources = ["*", "endpoint"]
          actions = ["*"]
        }
        l7_access {
          resources = ["*", "number2"]
          actions = ["*", "write"]
        }
      }
    }
    access {
//      roles = [banyan_role.test-role.name]
      roles = ["roleeee"]
      rules {
        conditions {
          trust_level = "Low"
        }
        l7_access {
          resources = ["*", "endpoint"]
          actions = ["*"]
        }
      }
    }
    exception {
      src_addr = ["127.0.0.1/32"]
    }
    options {
      disable_tls_client_authentication = true
      l7_protocol = "http"
    }
  }
}

resource "banyan_role" "test-role" {
 name = "realtfpolicytest"
  description = "realdescription"
  metadatatags {
    template = "USER"
  }
  spec {
    known_device_only = true
    platform = ["macOS", "Android"]
    group = ["Everyone", "admins"]
    email = ["john@marsha.com"]
    device_ownership = ["Corporate Dedicated", "Employee Owned",]
    mdm_present = true
  }
}
//
//resource "banyan_policy_attachment" "test-attachment" {
//  policy_id = banyan_policy.test-policy.id
//  attached_to_type = "service"
//  attached_to_id = banyan_service.test-service.id
//  is_enforcing = true
//}