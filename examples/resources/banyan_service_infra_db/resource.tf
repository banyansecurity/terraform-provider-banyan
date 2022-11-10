resource "banyan_service_db" "example" {
  name           = "example-db"
  description    = "some database service description"
  access_tier    = "us-west1"
  domain         = "example-db.us-west1.mycompany.com"
  backend_domain = "example-db.internal"
  backend_port   = 3306
}