data "banyan_policy_tunnel" "example" {
    name = "my-example-policy"
}

resource "banyan_service_tunnel" "example" {
  name         = "example-anyone-high"
  description  = "tunnel allowing anyone with a high trust level"
  access_tiers = [banyan_accesstier.example.name]
  policy       = data.banyan_policy_tunnel.example.id
}