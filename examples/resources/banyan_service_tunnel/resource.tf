# Example access tier with service tunnel and policy

resource "banyan_accesstier" "example" {
  name         = "example"
  address      = "*.example.mycompany.com"
  api_key_id   = "example"
  tunnel_cidrs = ["10.10.1.0/24"]
}

resource "banyan_service_tunnel" "example" {
  name        = "example"
  description = "allows access to ${banyan_accesstier.example.name} service tunnel"
  access_tier = banyan_accesstier.example.name
  policy      = banyan_policy_infra.example.id
}

resource "banyan_policy_infra" "example" {
  name        = banyan_accesstier.example.name
  description = "${banyan_accesstier.example.name} allow"
  access {
    roles       = ["ANY"]
    trust_level = "High"
  }
}
