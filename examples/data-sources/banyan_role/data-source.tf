data "banyan_role" "example" {
    name = "my-example-policy"
}

resource "banyan_service_web" "example" {
  name = "example-infra-service"
  policy = data.banyan_policy_infra.example.id
  
}