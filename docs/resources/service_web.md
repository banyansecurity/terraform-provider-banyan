# banyan_service_web (Resource)

Resource used for lifecycle management of web services. For more information see the documentation [here](https://docs.banyansecurity.io/docs/feature-guides/hosted-websites/).

### Example
```hcl
resource "banyan_service_web" "example" {
  name           = "example-web"
  description    = "some web service description"
  cluster        = "us-west"
  access_tier    = "us-west1"
  domain         = "example-web.corp.com"
  port           = 443
  backend_domain = "example-web.internal"
  backend_port   = 8443
}
```

### Required

- **backend_domain** (String) The internal network address where this service is hosted; ex. 192.168.1.2; set to "" if using http_connect
- **backend_port** (Number) The internal port where this service is hosted
- **domain** (String) The external-facing network address for this service; ex. website.example.com
- **name** (String) Name of the service; use lowercase alphanumeric characters or "-"

### Optional

- **access_tier** (String) Name of the access_tier which will proxy requests to your service backend; set to "" if using Global Edge deployment'
- **backend_tls** (Boolean) Indicates whether the connection to the backend server uses TLS.
- **backend_tls_insecure** (Boolean) Indicates the connection to the backend should not validate the backend server TLS certficate
- **cluster** (String) Name of the cluster used for your deployment; for Global Edge set to "global-edge", for Private Edge set to "cluster1"
- **connector** (String) Name of the connector which will proxy requests to your service backend; set to "" if using Private Edge deployment
- **description** (String) Description of the service
- **letsencrypt** (Boolean) Use a Public CA-issued server certificate instead of a Private CA-issued one
- **port** (Number) The external-facing port for this service

### Read-Only

- **id** (String) Id of the service
