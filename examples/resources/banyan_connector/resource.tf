resource "banyan_api_key" "example" {
  name              = "%s"
  description       = "realdescription"
  scope             = "satellite"
}

resource "banyan_connector" "example" {
  name              = "%s"
  api_key_id 		= banyan_api_key.example.id
}