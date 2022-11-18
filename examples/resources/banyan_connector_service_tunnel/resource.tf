resource "banyan_api_key" "example" {
  name        = "example"
  description = "some connector description"
  scope       = "satellite"
}

resource "banyan_connector" "example" {
  name       = "example"
  api_key_id = banyan_api_key.example.id
  cidrs      = ["10.5.0.1/24"]
  domains    = ["example.com"]
}

resource "banyan_policy_tunnel" "example" {
  name        = "example"
  description = "some tunnel policy description"
  access {
    roles       = ["ANY"]
    trust_level = "High"
  }
}

resource "banyan_service_tunnel" "example" {
  name        = "example"
  description = "some service tunnel description"
  connectors  = [banyan_connector.example.name]
  policy      = banyan_policy_tunnel.example.id
}