terraform {
  required_providers {
    banyan = {
      source  = "github.com/banyansecurity/banyan"
      version = "0.4.3"
    }
  }
}

provider "banyan" {
  api_token = var.banyan_api_token
  host      = var.banyan_host
}

resource "banyan_service" "example-web-service" {
  name        = "example-web-service"
  description = "some description"
  cluster     = "us-west"
  host_tag_selector = [
    { "com.banyanops.hosttag.site_name" = "us-west1" }
  ]
  frontend {
    port = 443
  }
  backend {
    target {
      port = 443
    }
  }
  metadatatags {
    service_app_type = "WEB"
    user_facing      = true
  }
}

resource "banyan_policy" "high-trust-any" {
  name        = "example"
  description = "Allows any user with a high trust score"
  metadatatags {
    template = "USER"
  }
  access {
    roles       = ["ANY"]
    trust_level = "High"
  }
  l7_protocol = "http"
}

resource "banyan_role" "everyone" {
  name        = "everyone"
  description = "all users"
  user_group  = ["Everyone"]
}

resource "banyan_policy_attachment" "example-high-trust-any" {
  policy_id        = banyan_policy.high-trust-any.id
  attached_to_type = "service"
  attached_to_id   = banyan_service.example-web-service.id
  is_enforcing     = true
}
