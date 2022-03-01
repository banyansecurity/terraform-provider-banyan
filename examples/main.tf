terraform {
  required_providers {
    banyan = {
      version = "0.1"
      source  = "github.com/banyansecurity/banyan"
    }
  }
}

provider "banyan" {
  refresh_token = var.banyan_refresh_token
  host          = var.banyan_host
}


resource "banyan_service" "example" {
  name = "example"
  cluster = "us-west1"
  frontend {
    port = 443
  }
  host_tag_selector = [
    { "com.banyanops.hosttag.site_name" = "us-west-1" }
  ]
  backend {
    target {
      port = 443
    }
  }
}

resource "banyan_policy" "example" {
  name        = "example"
  description = "realdescription"
  metadatatags {
    template = "USER"
  }
  access {
    roles                             = ["ANY", "HI"]
    trust_level                       = "High"
    l7_access {
      resources = ["*"]
      actions   = ["*"]
    }
  }
  disable_tls_client_authentication = true
  l7_protocol                       = "http"
}

resource "banyan_policy_attachment" "example" {
  policy_id        = banyan_policy.example.id
  attached_to_type = "service"
  attached_to_id   = banyan_service.example.id
  is_enforcing     = true
}
