resource "banyan_policy_tunnel" "example" {
  name        = "corporate-network-users"
  description = "some tunnel policy description"
  access {
    roles       = ["Everyone"]
    trust_level = "High"
  }
}

## Example Usage with Layer 4 Access Policy

resource "banyan_policy_tunnel" "example" {
  name        = "corporate-network-users"
  description = "some tunnel policy description"
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
  access {
    roles       = ["Corporate"]
    trust_level = "Medium"
    l4_access {
      allow {
        cidrs     = ["10.10.10.0/24"]
        protocols = ["TCP"]
        ports     = ["443"]
        fqdns = ["www.allowthisfqdn.com"]
      }
      deny {
        cidrs = ["10.1.1.0/24"]
        protocols = ["UDP","ICMP"]
        ports = ["8081","8082"]
        fqdns = ["www.denythisfqdn.com"]
      }
    }
  }
}

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