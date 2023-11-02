data "banyan_role" "example" {
    name = "my-example-role"
}

resource "banyan_policy_web" "example" {
  name = "example-web-policy"
  description = "example policy"
  access {
    roles       = [data.banyan_role.example.id]
    trust_level = "High"
  }
}