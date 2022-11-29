resource "banyan_policy_infra" "example" {
  name        = "example"
  description = "some infrastructure policy description"
  access {
    roles       = ["ANY"]
    trust_level = "High"
  }
}