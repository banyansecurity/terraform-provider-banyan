terraform {
  required_providers {
    banyan = {
      source = "github.com/banyansecurity/banyan"
      version = "0.4.1"
    }
  }
}

provider "banyan" {
  api_token = var.banyan_api_token
  host          = var.banyan_host
}

resource "banyan_service" "example" {
  name = local.service_name
  cluster = "us-west1"
  frontend {
    port = local.frontend_port
  }
  host_tag_selector = [
    { "com.banyanops.hosttag.site_name" = "us-west-1" }
  ]
  backend {
    target {
      port = local.backend_port
    }
  }
}

resource "banyan_policy" "high-trust-any" {
  name        = "example"
  description = "Allows any user with a high trust score"
  metadatatags {
    template = "USER"
  }
  access {
    roles                             = [banyan_role.everyone.name]
    trust_level                       = "Low"
  }
}

resource "banyan_role" "everyone" {
  name = "everyone"
  description = "all users"
  user_group = ["Everyone"]
}

resource "banyan_policy_attachment" "example-high-trust-any" {
  policy_id        = banyan_policy.high-trust-any.id
  attached_to_type = "service"
  attached_to_id   = banyan_service.example.id
  is_enforcing     = true
}
