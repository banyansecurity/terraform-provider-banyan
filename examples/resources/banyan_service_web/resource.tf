resource "banyan_service_web" "example" {
  name           = "example-web"
  access_tier    = "us-west1"
  domain         = "example-web.us-west1.mycompany.com"
  backend_domain = "example-web.internal"
  backend_port   = 8443
  policy         = banyan_policy_web.example.id
}