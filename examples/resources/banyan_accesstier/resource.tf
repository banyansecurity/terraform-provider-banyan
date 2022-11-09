resource "banyan_accesstier" "example" {
  name       = "example-accesstier"
  address    = "*.example-accesstier.mycompany.com"
  api_key_id = banyan_api_key.example.id
}

resource "banyan_api_key" "example" {
  name        = banyan_accesstier.example.name
  description = "${banyan_accesstier.example.name} access tier api key"
  scope       = "access_tier"
}