resource "banyan_policy_tunnel" "example" {
  name        = "example"
  description = "some tunnel policy description"
  access {
    roles       = ["Everyone"]
    trust_level = "Low"
    l4_access {
      allow {
        cidrs     = ["10.10.10.0/24"]
        protocols = ["TCP"]
        ports     = ["443"]
      }
      deny {
        cidrs     = ["10.10.10.0/24"]
        protocols = ["TCP"]
        ports     = ["80"]
      }
    }
  }
}