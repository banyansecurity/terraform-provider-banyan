<a id="ssh-service"></a>
## SSH Service
### Example
```hcl
resource "banyan_ssh_service" "acctest-ssh" {
  name               = "ssh-service"
  description        = "some ssh service"
  cluster            = "us-west"
  access_tiers       = ["us-west1", "us-east1"]
  domain             = "ssh-service.corp.com"
  user_facing        = true
  ssh_service_type   = "TRUSTCERT"
  write_ssh_config   = true
  ssh_chain_mode     = false
  ssh_host_directive = "ssh-service.corp.com"
  frontend {
    port = 1234
  }
  backend {
    target {
      name = "ssh-service.internal"
      port = 22
    }
  }
}
```
### SSH Service Schema
#### Required
- **name** (String) Name of the service
- **description** (String) Description of the service
- **cluster** (String) Name of the NetAgent cluster which the service is accessible from
- **access_tiers** (Set of String) Access tiers the service is accessible from
- **domain** (String) The publicly resolvable service domain name
- **ssh_chain_mode** (Boolean) Whether SSH chain mode should be enabled
- **ssh_host_directive** (String) Creates and entry in the SSH config file using the Host keyword
- **ssh_service_type** (String) The SSH certificate authentication type. Must be "TRUSTCERT" or "BOTH". "BOTH" indicates that SSHCert and TRUSTCERT are used when authenticating a user
- **write_ssh_config** (Boolean) Whether the client app should write to the users SSH config file
- **frontend** (Block List, Min: 1) Specifies the IP addresses and ports the frontend of the service listens on (see [below for nested schema](#nestedblock--frontend))
- **backend** (Block List, Min: 1) Backend specifies how Netagent, when acting as a reverse proxy, forwards incoming “frontend connections” to a backend workload instance that implements a registered service (see [below for nested schema](#nestedblock--backend))

#### Optional
- **tls_sni** (Set of String) If TLSSNI is set, Netagent will reject all non-TLS connections. It will only forward on TLS connections where the SNI matches for Policy validation.
- **cert_settings** (Block List, Max: 1) Specifies the X.509 server certificate to use for this Service (see [below for nested schema](#nestedblock--cert_settings))
- **user_facing** (Boolean) Whether the service is user-facing or not
- **icon** (String) Name of the icon to be displayed to the end user. Icon names are available in the Banyan UI

#### Read-Only
- **id** (String) ID of the service
