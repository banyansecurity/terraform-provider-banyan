data "banyan_role" "example" {
    name = "my-example-policy"
}

resource "banyan_service_web" "example" {
  name = "example-infra-service"
  policy = data.banyan_policy_infra.example.id
  backend_domain = "backend-domain.com"
  domain         = "my-domain.com"
}