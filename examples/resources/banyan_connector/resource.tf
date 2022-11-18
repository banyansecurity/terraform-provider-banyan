resource "banyan_api_key" "example" {
  name        = "example"
  description = "some connector description"
  scope       = "satellite"
}

resource "banyan_connector" "example" {
  name       = "example"
  api_key_id = banyan_api_key.example.id
}