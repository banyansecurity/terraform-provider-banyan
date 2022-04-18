# banyan_service_infra_k8s

Resource used for lifecycle management of kubernetes services. For more information see the documentation [here](https://docs.banyansecurity.io/docs/feature-guides/infrastructure/k8s-api/).

### Example
```hcl
resource "banyan_service_infra_k8s" "example" {
  name                            = "example-k8s"
  description                     = "some k8s service description"
  cluster                         = "us-west"
  access_tier                     = "us-west1"
  domain                          = "example-k8s.corp.com"
  backend_dns_override_for_domain = "example-k8s.service"
  client_kube_cluster_name        = "k8s-cluster"
  client_kube_ca_key              = "k8scAk3yH3re"
  client_banyanproxy_listen_port  = "9119"
}
```

### Required

- **backend_dns_override_for_domain** (String) Override DNS for service domain name with this value
- **client_kube_ca_key** (String) CA Public Key generated during Kube-OIDC-Proxy deployment
- **client_kube_cluster_name** (String) Creates an entry in the Banyan KUBE config file under this name and populates the associated configuration parameters
- **domain** (String) The external-facing network address for this service; ex. website.example.com
- **name** (String) Name of the service; use lowercase alphanumeric characters or "-"

### Optional

- **access_tier** (String) Name of the access_tier which will proxy requests to your service backend; set to "" if using Global Edge deployment'
- **client_banyanproxy_listen_port** (Number) Local listen port to be used by client proxy; if not specified, a random local port will be used
- **cluster** (String) Name of the cluster used for your deployment; for Global Edge set to "global-edge", for Private Edge set to "cluster1"
- **connector** (String) Name of the connector which will proxy requests to your service backend; set to "" if using Private Edge deployment
- **description** (String) Description of the service
- **port** (Number) The external-facing port for this service

### Read-Only

- **backend_domain** (String) For K8S, we use Client Specified connectivity
- **backend_http_connect** (Boolean) For K8S, we use Client Specified connectivity
- **backend_port** (Number) For K8S, we use Client Specified connectivity
- **id** (String) Id of the service
