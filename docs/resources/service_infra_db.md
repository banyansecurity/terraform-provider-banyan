# banyan_service_infra_db

Resource used for lifecycle management of database services. For more information see the documentation [here.](https://docs.banyansecurity.io/docs/feature-guides/infrastructure/databases/)

### Example
```hcl
resource "banyan_service_infra_db" "example" {
  name        = "example-database"
  description = "some database service description"
  cluster      = "us-west"
  access_tiers   = ["us-west1"]
  domain      = "example-database.corp.com"
  backend {
    domain = "example-database.internal"
    port = 7823
  }
}
```
### Database Service Schema
#### Required
- **name** (String) Name of the service
- **description** (String) Description of the service
- **cluster** (String) Name of the NetAgent cluster which the service is accessible from
- **domain** (String) The publicly resolvable service domain name
- **port** (String) The port that the service listens on
- **backend** (Block List, Min: 1) Backend specifies how Netagent, when acting as a reverse proxy, forwards incoming “frontend connections” to a backend workload instance that implements a registered service (see [below for nested schema](#nestedblock--backend))

#### Optional
- **access_tiers** (Set of String) Access tiers the service is accessible from
- **connector** (String) Name of the connector which will proxy requests to your service backend; set to "" if using Private Edge deployment
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

- **domain** (String) The internal network address where this service is hosted; ex. 192.168.1.2; set to "" if using backend_http_connect
- **port** (Number) The internal port where this service is hosted; set to 0 if using backend_http_connect

Optional:

- **http_connect** (Boolean) Indicates to use HTTP Connect request to derive the backend target address
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


<a id="nestedblock--cert_settings"></a>
### Nested Schema for `cert_settings`

Optional:

- **dns_names** (Set of String) DNSNames specifies how to populate the CommonName field in the X.509
  server certificate for this Service. If DNSNames is not specified the
  CommonName field will be set to the ServiceName. Any DNS names specified will be added to the CommonName field of the certificate.
