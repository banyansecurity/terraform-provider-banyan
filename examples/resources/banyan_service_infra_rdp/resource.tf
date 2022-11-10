resource "banyan_service_infra_rdp" "example" {
  name           = "example-rdp"
  description    = "some RDP service description"
  access_tier    = "us-west1"
  domain         = "example-rdp.us-west1.mycompany.com"
  backend_domain = "10.1.34.54"
  backend_port   = 3389
}