# banyan_service_infra_db

Resource used for lifecycle management of database services. For more information see the documentation [here](https://docs.banyansecurity.io/docs/feature-guides/infrastructure/databases/).

### Example
```hcl
resource "banyan_service_infra_db" "example" {
  name        = "example-db"
  description = "some database service description"
  cluster      = "us-west"
  access_tier   = "us-west1"
  domain      = "example-db.corp.com"
  backend_domain = "example-database.internal"
  backend_port = 0
  http_connect = true
}
```

### Required

- **domain** (String) The external-facing network address for this service; ex. website.example.com
- **name** (String) Name of the service; use lowercase alphanumeric characters or "-"

### Optional

- **access_tier** (String) Name of the access_tier which will proxy requests to your service backend; set to "" if using Global Edge deployment'
- **backend_domain** (String) The internal network address where this service is hosted; ex. 192.168.1.2; set to "" if using http_connect
- **http_connect** (Boolean) Indicates to use HTTP Connect request to derive the backend target address.
- **backend_port** (Number) The internal port where this service is hosted; set to 0 if using http_connect
- **client_banyanproxy_allowed_domains** (Set of String) Restrict which domains can be proxied through the banyanproxy; only used with Client Specified connectivity
- **client_banyanproxy_listen_port** (Number) Local listen port to be used by client proxy; if not specified, a random local port will be used
- **cluster** (String) Name of the cluster used for your deployment; for Global Edge set to "global-edge", for Private Edge set to "cluster1"
- **connector** (String) Name of the connector which will proxy requests to your service backend; set to "" if using Private Edge deployment
- **description** (String) Description of the service
- **port** (Number) The external-facing port for this service

### Read-Only

- **id** (String) Id of the service
