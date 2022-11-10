resource "banyan_service_infra_tcp" "example" {
  name           = "example-tcp"
  description    = "some tcp service description"
  access_tier    = "us-west1"
  domain         = "example-tcp.us-west1.mycompany.com"
  backend_domain = "example-tcp.internal"
  backend_port   = 5673
}