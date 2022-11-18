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
    roles        = ["Admins"]
    trust_level  = "High"
    l7_resources = ["/admin"]
    l7_actions   = ["READ"]
  }

  access {
    roles        = ["ANY"]
    trust_level  = "High"
    l7_resources = ["/app"]
    l7_actions   = ["READ"]
  }
}