# banyan_service_infra_ssh (Resource)

Resource used for lifecycle management of SSH services. For more information see the documentation [here](https://docs.banyansecurity.io/docs/feature-guides/infrastructure/ssh-servers/).

### Example
```hcl
resource "banyan_service_infra_ssh" "example" {
  name                      = "example-ssh"
  description               = "some SSH service description"
  cluster                   = "us-west"
  access_tier               = "us-west1"
  domain                    = "example-ssh.corp.com"
  backend_domain            = "example-ssh.internal"
  backend_port              = 22
  client_ssh_host_directive = "example-ssh.corp.com"
}
```

### Required

- **domain** (String) The external-facing network address for this service; ex. website.example.com
- **name** (String) Name of the service; use lowercase alphanumeric characters or "-"

### Optional

- **access_tier** (String) Name of the access_tier which will proxy requests to your service backend; set to "" if using Global Edge deployment'
- **backend_domain** (String) The internal network address where this service is hosted; ex. 192.168.1.2; set to "" if using backend_http_connect
- **backend_http_connect** (Boolean) Indicates to use HTTP Connect request to derive the backend target address.
- **backend_port** (Number) The internal port where this service is hosted; set to 0 if using backend_http_connect
- **client_ssh_auth** (String) Specifies which certificates - TRUSTCERT | SSHCERT | BOTH - should be used when the user connects to this service; default: TRUSTCERT
- **client_ssh_host_directive** (String) Creates an entry in the SSH config file using the Host keyword. Wildcards are supported such as "192.168.*.?"; default: <service name>
- **cluster** (String) Name of the cluster used for your deployment; for Global Edge set to "global-edge", for Private Edge set to "cluster1"
- **connector** (String) Name of the connector which will proxy requests to your service backend; set to "" if using Private Edge deployment
- **description** (String) Description of the service
- **port** (Number) The external-facing port for this service

### Read-Only

- **client_banyanproxy_listen_port** (Number) For SSH, banyanproxy uses stdin instead of a local port
- **id** (String) Id of the service
