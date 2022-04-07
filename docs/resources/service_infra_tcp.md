# banyan_service_infra_tcp

Resource used for lifecycle management of generic TCP services. For more information see the documentation [here.](https://docs.banyansecurity.io/docs/feature-guides/infrastructure/tcp-services/)

### Example
```hcl
resource "banyan_service_infra_tcp" "example" {
  name           = "example-tcp"
  description    = "some tcp service description"
  cluster        = "us-west"
  access_tiers   = ["us-west1"]
  user_facing    = true
  domain         = "example-tcp.corp.com"
  backend_domain = "example-tcp.internal"
  backend_port   = 5673
}
```
### TCP Service Schema
#### Required
- **name** (String) Name of the service
- **description** (String) Description of the service
- **cluster** (String) Name of the NetAgent cluster which the service is accessible from
- **access_tiers** (Set of String) Access tiers the service is accessible from
- **domain** (String) The publicly resolvable service domain name
- **frontend** (Block List, Min: 1) Specifies the IP addresses and ports the frontend of the service listens on (see [below for nested schema](#nestedblock--frontend))
- **backend** (Block List, Min: 1) Backend specifies how Netagent, when acting as a reverse proxy, forwards incoming “frontend connections” to a backend workload instance that implements a registered service (see [below for nested schema](#nestedblock--backend))

#### Optional
- **tls_sni** (Set of String) If TLSSNI is set, Netagent will reject all non-TLS connections. It will only forward on TLS connections where the SNI matches for Policy validation.
- **cert_settings** (Block List, Max: 1) Specifies the X.509 server certificate to use for this Service (see [below for nested schema](#nestedblock--cert_settings))
- **user_facing** (Boolean) Whether the service is user-facing or not
- **icon** (String) Name of the icon to be displayed to the end user. Icon names are available in the Banyan UI
- **description_link** (String) Link shown to end users

#### Read-Only
- **id** (String) ID of the service

<a id="nestedblock--backend"></a>
### Nested Schema for `backend`

Required:

- **target** (Block List, Min: 1, Max: 1) Specifies the backend workload instance's address or name ports, and TLS properties. (see [below for nested schema](#nestedblock--backend--target))

Optional:

- **connector_name** (String) If Banyan Connector is used to access this service, this must be set to the name of the connector with network access to the service
- **dns_overrides** (Map of String) Specifies name-to-address or name-to-name mappings.
  Name-to-address mapping could be used instead of DNS lookup. Format is "FQDN: ip_address".
  Name-to-name mapping could be used to override one FQDN with the other. Format is "FQDN1: FQDN2"
  Example: name-to-address -> "internal.myservice.com" : "10.23.0.1"
  ame-to-name    ->    "exposed.service.com" : "internal.myservice.com"

<a id="nestedblock--backend--target"></a>
### Nested Schema for `backend.target`

Required:

- **port** (Number) Port specifies the backend server's TCP port number


<a id="nestedblock--frontend"></a>
### Nested Schema for `frontend`

Required:

- **port** (String) The port that the service listens on


<a id="nestedblock--cert_settings"></a>
### Nested Schema for `cert_settings`

Optional:

- **dns_names** (Set of String) DNSNames specifies how to populate the CommonName field in the X.509
  server certificate for this Service. If DNSNames is not specified the
  CommonName field will be set to the ServiceName. Any DNS names specified will be added to the CommonName field of the certificate.
