resource "banyan_service_infra_k8s" "example" {
  name                            = "example-k8s"
  description                     = "some k8s service description"
  access_tier                     = "us-west1"
  domain                          = "example-k8s.us-west1.mycompany.com"
  backend_domain                  = "example-k8s.internal"
  backend_dns_override_for_domain = "example-k8s.service"
  client_kube_cluster_name        = "k8s-cluster"
  client_kube_ca_key              = "k8scAk3yH3re"
  policy                          = banyan_policy_infra.example.id
}