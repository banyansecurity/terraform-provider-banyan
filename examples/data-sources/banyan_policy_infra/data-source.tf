data "banyan_policy_infra" "example" {
    name = "my-example-policy"
}

resource "banyan_service_tcp" "example" {
  name           = "example-tcp"
  description    = "some tcp service description"
  access_tier    = "us-west1"
  domain         = "example-tcp.us-west1.mycompany.com"
  backend_domain = "example-tcp.internal"
  backend_port   = 5673
  policy         = data.banyan_policy_infra.example.id
}

resource "banyan_service_db" "example" {
  name           = "example-db"
  description    = "some database service description"
  access_tier    = "us-west1"
  domain         = "example-db.us-west1.mycompany.com"
  backend_domain = "example-db.internal"
  backend_port   = 3306
  policy         = data.banyan_policy_infra.example.id
}

resource "banyan_service_k8s" "example" {
  name                            = "example-k8s"
  description                     = "some k8s service description"
  access_tier                     = "us-west1"
  domain                          = "example-k8s.us-west1.mycompany.com"
  backend_domain                  = "example-k8s.internal"
  backend_dns_override_for_domain = "example-k8s.service"
  client_kube_cluster_name        = "k8s-cluster"
  client_kube_ca_key              = "k8scAk3yH3re"
  policy                          = data.banyan_policy_infra.example.id
}