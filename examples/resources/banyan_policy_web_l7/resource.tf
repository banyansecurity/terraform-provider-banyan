resource "banyan_service_web" "example" {
  name           = "example-web"
  access_tier    = "us-west1"
  domain         = "example-web.corp.com"
  backend_domain = "example-web.internal"
  backend_port   = 8443
  policy         = banyan_policy_web.example.id
}

resource "banyan_policy_web" "example" {
  name        = "example"
  description = "some web policy description"

  access {
    roles       = ["Administrators"]
    trust_level = "High"
    l7_access {
      resources = ["/admin"]
      actions   = ["READ"]
    }
  }

  access {
    roles       = ["Everyone"]
    trust_level = "High"
    l7_access {
      resources = ["/app"]
      actions   = ["READ"]
    }
  }
}
