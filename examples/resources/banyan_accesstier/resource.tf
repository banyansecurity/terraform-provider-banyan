resource "banyan_api_key" "example" {
  name        = "example api key"
  description = "example api key"
  scope       = "access_tier"
}

resource "banyan_accesstier" "example" {
  name       = "example"
  address    = "*.example.mycompany.com"
  api_key_id = banyan_api_key.example.id
}