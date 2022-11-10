resource "banyan_api_key" "example" {
  name        = "example api key"
  description = "example api key"
  scope       = "access_tier"
}

resource "banyan_accesstier" "example" {
  name         = "example"
  address      = "*.example.mycompany.com"
  api_key_id   = banyan_api_key.example.name
  tunnel_cidrs = ["10.10.1.0/24"]
}

resource "banyan_service_tunnel" "example" {
  name        = "example-anyone-high"
  description = "tunnel allowing anyone with a high trust level"
  access_tier = banyan_accesstier.example.name
  policy      = banyan_policy_infra.anyone-high.id
}

resource "banyan_policy_infra" "anyone-high" {
  name        = "allow anyone"
  description = "${banyan_accesstier.example.name} allow"
  access {
    roles       = ["ANY"]
    trust_level = "High"
  }
}