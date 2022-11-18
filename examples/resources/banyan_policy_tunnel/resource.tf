resource "banyan_policy_tunnel" "anyone-high" {
  name        = "corporate-network-users"
  description = "${banyan_accesstier.example.name} allow users"
  access {
    roles       = ["ANY"]
    trust_level = "High"
    l4_access_allow {
      cidrs     = ["10.10.1.0/24"]
      protocols = ["TCP"]
      ports     = ["443"]
    }
  }
}