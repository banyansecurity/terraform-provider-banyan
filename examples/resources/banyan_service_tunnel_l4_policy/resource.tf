resource "banyan_api_key" "example" {
  name        = "example api key"
  description = "example api key"
  scope       = "access_tier"
}

resource "banyan_accesstier" "example" {
  name         = "example"
  address      = "*.example.mycompany.com"
  api_key_id   = banyan_api_key.example.name
  tunnel_cidrs = ["10.10.0.0/16"]
}

resource "banyan_service_tunnel" "users" {
  name         = "corporate network"
  description  = "tunnel allowing anyone with a high trust level access to 443"
  access_tiers = [banyan_accesstier.example.name]
  policy       = banyan_policy_tunnel.anyone-high.id
}

resource "banyan_service_tunnel" "administrators" {
  name         = "corporate network admin"
  description  = "tunnel allowing administrators access to the networks"
  access_tiers = [banyan_accesstier.example.name]
  policy       = banyan_policy_tunnel.administrators.id
}

resource "banyan_policy_tunnel" "anyone-high" {
  name        = "allow anyone"
  description = "${banyan_accesstier.example.name} allow"
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

resource "banyan_policy_tunnel" "administrators" {
  name        = "allow only administrators access to the entire network"
  description = "${banyan_accesstier.example.name} allow"
  access {
    roles       = ["Administrators"]
    trust_level = "High"
  }
}