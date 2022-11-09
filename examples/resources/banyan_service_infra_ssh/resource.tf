resource "banyan_service_infra_ssh" "example" {
  name           = "example-ssh"
  description    = "some SSH service description"
  access_tier    = "us-west1"
  domain         = "example-ssh.us-west1.mycompany.com"
  backend_domain = "10.3.53.12"
  backend_port   = 22
}