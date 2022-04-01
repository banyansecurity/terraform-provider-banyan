page_title: "banyan_service_custom Resource - terraform-provider-banyan"
subcategory: ""
description: |-
Banyan policy for controlling access to a service
---

# banyan_service_infra_db (Resource)

Resource used for lifecycle management of infrastructure database services.

### Example
```hcl
resource "banyan_service_infra_db" "example" {
  name         = "database-service"
  description  = "some database service description"
  cluster      = "us-west"
  access_tiers = ["us-west1"]
  user_facing  = true
  domain       = "database-service.corp.com"
  frontend {
    port = 845
  }
  backend {
    target {
      name = "database-service.internal"
      port = 8845
    }
  }
}
```
### Database Service Schema
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

#### Read-Only
- **id** (String) ID of the service
