resource "banyan_policy_tunnel" "anyone-high" {
  name        = "corporate-network-users"
  description = "${banyan_accesstier.example.name} allow users"
  access {
    roles       = ["Everyone"]
    trust_level = "High"
    l4_access {
      allow {
        cidrs     = ["10.10.10.0/24"]
        protocols = ["TCP"]
        ports     = ["443"]
      }
    }
  }
}

resource "banyan_policy_tunnel" "example" {
  name        = "example-policy"
  description = "Example policy description"
  access {
    roles       = ["role1", "role2"]
    trust_level = "Medium"
    l4_access {
      allow {
        cidrs     = ["10.0.0.0/24"]
        protocols = ["TCP", "UDP"]
        ports     = ["8080", "443","80"]
        fqdns     = ["example.com"]
      }
      deny {
        cidrs     = ["192.168.0.0/16"]
        protocols = ["TCP"]
        ports     = ["8443"]
        fqdns     = ["example.org"]
      }
    }
  }
}