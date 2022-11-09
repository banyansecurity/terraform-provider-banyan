resource "banyan_policy_web" "example" {
  name        = "example"
  description = "some web policy description"
    access {
      roles                             = ["ANY"]
      trust_level                       = "High"
    }
}