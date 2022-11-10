resource "banyan_api_key" "example" {
  name        = "my-connector"
  description = "realdescription"
  scope       = "satellite"
}

resource "banyan_connector" "example" {
  name    = "my-connector"
  api_key = banyan_api_key.example.name
  domains = ["my-connector.mycompany.com"]
}