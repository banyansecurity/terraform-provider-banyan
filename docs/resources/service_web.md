# banyan_service_web

Resource used for lifecycle management of web services. For more information see the documentation [here.](https://docs.banyansecurity.io/docs/feature-guides/hosted-websites/)

### Example Using Access Tier
```hcl
resource "banyan_service_web" "example" {
  name        = "example-web"
  description = "some web service description"
  cluster     = "us-west"
  access_tiers   = ["us-west1"]
  protocol = "https"
  domain = "example-web.corp.com"
  port = 443
  backend {
    domain = "example-web.internal"
    port = 8443
  }
}
```

### Example Using Connector
```hcl
resource "banyan_service_web" "example" {
  name        = "example-web"
  description = "some web service description"
  cluster     = "us-west"
  connector   = "connector-us-west1"
  protocol    = "https"
  domain      = "example-web.corp.com"
  port        = 443
  backend {
    domain = "example-web.internal"
    port = 8443
  }
}
```
### Web Service Schema
#### Required
- **name** (String) Name of the service
- **description** (String) Description of the service
- **cluster** (String) Name of the NetAgent cluster which the service is accessible from
- **access_tiers** (Set of String) Access tiers the service is accessible from
- **domain** (String) The publicly resolvable service domain name
- **protocol** (String) The protocol of the service, must be http or https
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

- **allow_patterns** (Block List) Defines the patterns for the backend workload instance. If the BackendAllowPatterns is set,
  then the backend must match at least one entry in this list to establish connection with the backend service.
  Note that this field is effective only when BackendWhitelist is not populated.
  If BackendWhitelist and BackendAllowPatterns are both not populated, then all backend
  address/name/port are allowed. This field could be used with httpConnect set to TRUE or FALSE. With HttpConnect set to FALSE,
  only backend hostnames are supported, all other fields are ignored. With HttpConnect set to TRUE,
  all fields of BackendAllowPatterns are supported and effective. (see [below for nested schema](#nestedblock--backend--allow_patterns))
- **connector_name** (String) If Banyan Connector is used to access this service, this must be set to the name of the connector with network access to the service
- **dns_overrides** (Map of String) Specifies name-to-address or name-to-name mappings.
  Name-to-address mapping could be used instead of DNS lookup. Format is "FQDN: ip_address".
  Name-to-name mapping could be used to override one FQDN with the other. Format is "FQDN1: FQDN2"
  Example: name-to-address -> "internal.myservice.com" : "10.23.0.1"
  ame-to-name    ->    "exposed.service.com" : "internal.myservice.com"
- **http_connect** (Boolean) Indicates to use HTTP Connect request to derive the backend target address.
- **whitelist** (Set of String) Indicates the allowed names for the backend workload instance.
  If this field is populated, then the backend name must match at least one entry
  in this field list to establish connection with the backend service.
  The names in this list are allowed to start with the wildcard character "*" to match more
  than one backend name. This field is used generally with HttpConnect=FALSE. For all HttpConnect=TRUE cases, or where
  more advanced backend defining patterns are required, use BackendAllowPatterns.

<a id="nestedblock--backend--target"></a>
### Nested Schema for `backend.target`

Required:

- **port** (Number) Port specifies the backend server's TCP port number

Optional:

- **client_certificate** (Boolean) Indicates whether to provide Netagent's client TLS certificate to the server if the server asks for it in the TLS handshake.
- **name** (String) Name specifies the DNS name of the backend workload instance.
  If it is the empty string, then Netagent will use the destination
  IP address of the incoming frontend connection as the workload
  instance's address
- **tls** (Boolean) TLS indicates whether the connection to the backend server uses TLS.
- **tls_insecure** (Boolean) TLSInsecure indicates whether the backend TLS connection does not validate the server's TLS certificate


<a id="nestedblock--backend--allow_patterns"></a>
### Nested Schema for `backend.allow_patterns`

Optional:

- **cidrs** (Set of String) Host may be a CIDR such as 10.1.1.0/24
- **hostnames** (Set of String) Allowed hostnames my include a leading and/or trailing wildcard character * to match multiple hostnames
- **ports** (Block List, Max: 1) List of allowed ports and port ranges (see [below for nested schema](#nestedblock--backend--allow_patterns--ports))

<a id="nestedblock--backend--allow_patterns--ports"></a>
### Nested Schema for `backend.allow_patterns.ports`

Optional:

- **port_list** (Set of Number) List of allowed ports
- **port_range** (Block List) List of allowed port ranges (see [below for nested schema](#nestedblock--backend--allow_patterns--ports--port_range))

<a id="nestedblock--backend--allow_patterns--ports--port_range"></a>
### Nested Schema for `backend.allow_patterns.ports.port_range`

Optional:

- **max** (Number) Maximum value of port range
- **min** (Number) Minimum value of port range


<a id="nestedblock--frontend"></a>
### Nested Schema for `frontend`

Required:

- **port** (String) The port that the service listens on

Optional:

- **cidr** (String) A list of IP addresses in string format specified in CIDR notation that the Service should match


<a id="nestedblock--cert_settings"></a>
### Nested Schema for `cert_settings`

Optional:

- **custom_tls_cert** (Block List, Max: 1) CustomTLSCert enables Netagent to override the default behavior
  of obtaining a X.509 server certificate for this Service from Shield,
  and instead use a TLS certificate on the local file system (see [below for nested schema](#nestedblock--cert_settings--custom_tls_cert))
- **dns_names** (Set of String) DNSNames specifies how to populate the CommonName field in the X.509
  server certificate for this Service. If DNSNames is not specified the
  CommonName field will be set to the ServiceName
- **letsencrypt** (Boolean) Letsencrypt flag will be used whether to request a letsencrypt certificate for given domains

<a id="nestedblock--cert_settings--custom_tls_cert"></a>
### Nested Schema for `cert_settings.custom_tls_cert`

Required:

- **cert_file** (String, Sensitive) Specifies the local path of the public certificate (ex: /etc/letsencrypt/live/intks.net-0001/fullchain.pem) on the netagent / connector filesystem
- **enabled** (Boolean) Turns on the custom TLS certificate capability
- **key_file** (String, Sensitive) Specifies the local path of the private key (ex: /etc/letsencrypt/live/intks.net-0001/fullchain.pem) on the netagent / connector filesystem



<a id="nestedblock--client_cidrs"></a>
### Nested Schema for `client_cidrs`

Optional:

- **cidr_address** (Block List) CIDRAddress uses the Classless Inter-Domain Routing (CIDR) format for flexible allocation of IP addresses (see [below for nested schema](#nestedblock--client_cidrs--cidr_address))
- **clusters** (Set of String) Tells Netagent to set Client CIDRs on only a specific subset of clusters
- **host_tag_selector** (List of Map of String) Tells Netagent to set Client CIDRs on only a specific subset of hosts and ports

<a id="nestedblock--client_cidrs--cidr_address"></a>
### Nested Schema for `client_cidrs.cidr_address`

Optional:

- **cidr** (String) Must be in CIDR format i.e. 192.168.0.0/16
- **ports** (String)



<a id="nestedblock--http_settings"></a>
### Nested Schema for `http_settings`

Required:

- **enabled** (Boolean) Enables http service specific settings

Optional:

- **exempted_paths** (Block List, Max: 1) Tells Netagent that specific HTTP paths should be whitelisted/exempted from OIDC authentication (see [below for nested schema](#nestedblock--http_settings--exempted_paths))
- **headers** (Map of String) Headers is a list of HTTP headers to add to every request sent to the Backend;
  the key of the map is the header name, and the value is the header value you want.
  The header value may be constructed using Go template syntax, such as
  referencing values in Banyan's JWT TrustToken.
- **http_health_check** (Block List, Max: 1) Tells Netagent that specific HTTP paths should be exempted from access control policies (see [below for nested schema](#nestedblock--http_settings--http_health_check))
- **oidc_settings** (Block List, Max: 1) OIDCSettings provides Netagent specific parameters needed to use
  OpenID Connect to authenticate an Entity for access to a Service (see [below for nested schema](#nestedblock--http_settings--oidc_settings))
- **token_loc** (Block List, Max: 1) Token location (see [below for nested schema](#nestedblock--http_settings--token_loc))

<a id="nestedblock--http_settings--exempted_paths"></a>
### Nested Schema for `http_settings.exempted_paths`

Required:

- **enabled** (Boolean) Turns on the HTTP exempted paths capability

Optional:

- **patterns** (Block List) Pattern tells Netagent to exempt HTTP requests based on matching HTTP request attributes
  such as source IP, host, headers, methods, paths, etc.
  For example, use this section when exempting CORS requests by source IP address. (see [below for nested schema](#nestedblock--http_settings--exempted_paths--patterns))

<a id="nestedblock--http_settings--exempted_paths--patterns"></a>
### Nested Schema for `http_settings.exempted_paths.patterns`

Optional:

- **hosts** (Block List) The host/origin header values in the HTTP request (see [below for nested schema](#nestedblock--http_settings--exempted_paths--patterns--hosts))
- **mandatory_headers** (Set of String) MandatoryHeaders (mandatory) matches the HTTP request headers.
  The matching request will have all of the headers listed.
  To list all the headers that a matching HTTP request should have for instance
  "Content-Type"/"Access-Control-Allow-Origin" etc.
  ["*"] will have "DONT CARE" effect and will skip matching headers.
- **methods** (Set of String) Matches the HTTP request methods. The matching request
  will have any one of the listed methods.
  To list all the methods supported "like GET/POST/OPTIONS etc.
  ["*"] value will have "DONT CARE" effect and will skip matching methods.
- **paths** (Set of String) Matches the HTTP request URI. The matching request will have any one of the paths/strings listed.
- **source_cidrs** (Set of String) Specifies the source IP address of the HTTP request.
  The matching request should match or should be in the range of the CIDR specified.
  SourceCIDRs is an array and multiple CIDRs with/without prefix
  could be specified like, 127.0.0.1, 192.168.1.0/29, 10.0.0.0/8 etc.
  If source-ip matching is not required, please skip this field
- **template** (String)

<a id="nestedblock--http_settings--exempted_paths--patterns--hosts"></a>
### Nested Schema for `http_settings.exempted_paths.patterns.template`

Optional:

- **origin_header** (Set of String) OriginHeader (mandatory)-is list of web host address.
  The web-host address matches to contents of Origin header in the HTTP request.
  The value should have "scheme:host:port", ex: "https://www.banyansecurity.io:443".
  This field supports single domain wildcards also, like
  https://*.banyansecurity.com or https://api.*.banyansecurity.com:443
- **target** (Set of String) Target (mandatory) list of web host address. In this web-host address,
  the hostname matches to host header in the HTTP request.
  The value should have "scheme:host:port",
  ex: https://www.banyansecurity.io:443. This field supports single domain wildcards also,
  like https://*.banyansecurity.com or https://api.*.banyansecurity.com:443.
  This should be filled only while hosting multi-domain services. In single domain
  service deployments, this field to be filled as [*] to have "DONT CARE" effect.




<a id="nestedblock--http_settings--http_health_check"></a>
### Nested Schema for `http_settings.http_health_check`

Required:

- **addresses** (Set of String) Addresses of the http health check
- **enabled** (Boolean) Turns on the HTTP health check capability
- **from_address** (Set of String) Allowed source addresses of the health checker (all allowed if omitted)
- **https** (Boolean) Specifies that the health check uses https instead of https
- **path** (String) Specifies the HTTP health check path

Optional:

- **method** (String) Specifies the health check HTTP method
- **user_agent** (String) A string to check for in the HTTP user-agent header (no check if omitted)


<a id="nestedblock--http_settings--oidc_settings"></a>
### Nested Schema for `http_settings.oidc_settings`

Required:

- **enabled** (Boolean) Turns on the OIDC capability
- **service_domain_name** (String) The URL used to access the service

Optional:

- **api_path** (String) default: /api) is the path serving AJAX requests.
  If a request is not authenticated, paths starting with the APIPath
  will receive a 403 Unauthorized response
  instead of a 302 Redirect to the authentication provider
- **post_auth_redirect_path** (String) The path to return the user to after OpenID Connect flow
- **suppress_device_trust_verification** (Boolean) SuppressDeviceTrustVerification disables Device Trust Verification for a service if set to true
- **trust_callbacks** (Map of String)


<a id="nestedblock--http_settings--token_loc"></a>
### Nested Schema for `http_settings.token_loc`

Required:

- **authorization_header** (Boolean)
- **custom_header** (String)
- **query_param** (String)



<a id="nestedblock--tag_slice"></a>
### Nested Schema for `tag_slice`

Required:

- **id** (String) The ID of this resource.
- **name** (String)
- **org_id** (String)
- **service_id** (String)
- **value** (String)
