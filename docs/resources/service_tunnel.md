---
page_title: "banyan_service_tunnel Resource - terraform-provider-banyan"
subcategory: ""
description: |-
  Resource used for lifecycle management of service tunnels. In order to properly function this resource must be utilized with the banyanaccesstier resource or banyanaccesstier2 terraform registry modules. Please see the example below and in the terraform modules for the respective cloud provider. For more information on service tunnels see the documentation https://docs.banyansecurity.io/docs/feature-guides/service-tunnels/
---

# banyan_service_tunnel (Resource)

Resource used for lifecycle management of service tunnels. In order to properly function this resource must be utilized with the banyan_accesstier resource or banyan_accesstier2 terraform registry modules. Please see the example below and in the terraform modules for the respective cloud provider. For more information on service tunnels see the documentation https://docs.banyansecurity.io/docs/feature-guides/service-tunnels/

## Example Usage
```terraform
resource "banyan_api_key" "example" {
  name        = "example api key"
  description = "example api key"
  scope       = "access_tier"
}

resource "banyan_accesstier" "example" {
  name         = "example"
  address      = "*.example.mycompany.com"
  api_key_id   = banyan_api_key.example.name
  tunnel_cidrs = ["10.10.1.0/24"]
}

resource "banyan_service_tunnel" "example" {
  name         = "example-anyone-high"
  description  = "tunnel allowing anyone with a high trust level"
  network_settings {
    cluster      = "cluster1"
    access_tiers = [banyan_accesstier.example.name]
  }
  policy       = banyan_policy_tunnel.anyone-high.id
  policy_enforcing = true
}

resource "banyan_service_tunnel" "example1" {
  name         = "example-anyone-high"
  description  = "tunnel allowing anyone with a high trust level"
  network_settings {
    cluster      = "cluster1"
    access_tiers = [banyan_accesstier.example.name]
  }
  network_settings {
    connectors = ["myconnector"]
    public_cidrs {
      include = ["8.8.8.8/32", "75.75.75.75/32", "75.75.76.76/32"]
      exclude = ["99.99.99.99/32"]
    }
    public_domains {
      include = ["cnn.com", "icanhazip.com", "fast.com", "yahoo.com", "banyansecurity.io"]
      exclude = ["excluded.com"]
    }
    applications {
      include = ["067c3a25-8271-4764-89dd-c3543ac99a5a", "0b90e7d0-e8fc-43fb-95b7-4ad5d6881bb8"]
      exclude = ["067c3a25-8271-4764-89dd-c3543ac99a5c"]
    }
  }
  network_settings {
    cluster = "cluster1"
    access_tiers = ["myaccesstier1"]
    public_cidrs {
      include = ["8.8.8.8/32", "75.75.75.75/32", "75.75.76.76/32"]
      exclude = ["99.99.99.99/32"]
    }
    public_domains {
      include = ["cnn.com", "icanhazip.com", "fast.com", "yahoo.com", "banyansecurity.io"]
      exclude = ["excluded.com"]
    }
    applications {
      include = ["067c3a25-8271-4764-89dd-c3543ac99a5a", "0b90e7d0-e8fc-43fb-95b7-4ad5d6881bb8"]
      exclude = ["067c3a25-8271-4764-89dd-c3543ac99a5c"]
    }
  }

  network_settings {
    cluster = "cluster1"
    access_tier_group = "atg"
    public_cidrs {
      include = ["8.8.8.8/32", "75.75.75.75/32", "75.75.76.76/32"]
      exclude = ["99.99.99.99/32"]
    }
    public_domains {
      include = ["cnn.com", "icanhazip.com", "fast.com", "yahoo.com", "banyansecurity.io"]
      exclude = ["excluded.com"]
    }
    applications {
      include = ["067c3a25-8271-4764-89dd-c3543ac99a5a", "0b90e7d0-e8fc-43fb-95b7-4ad5d6881bb8"]
      exclude = ["067c3a25-8271-4764-89dd-c3543ac99a5c"]
    }
  }
  name_resolution {
    name_servers = ["8.8.8.8"]
    dns_search_domains = ["mylocal.local"]
  }
  policy       = banyan_policy_tunnel.anyone-high.id
  policy_enforcing = true
}



resource "banyan_policy_tunnel" "anyone-high" {
  name        = "allow anyone"
  description = "${banyan_accesstier.example.name} allow"
  access {
    roles       = ["ANY"]
    trust_level = "High"
  }
}
```

## Example Service Tunnel with L4 Policy
```terraform
terraform {
  required_providers {
    banyan = {
      source  = "github.com/banyansecurity/banyan"
      version = ">=0.9.1"
    }
  }
}

provider "banyan" {
  api_key = "igKuZugo6yH3_ig04qE8mYEeqDcSi-5s_uQr9Td0zsI"
}

resource "banyan_api_key" "example" {
  name        = "example api key"
  description = "example api key"
  scope       = "access_tier"
}

resource "banyan_accesstier" "example" {
  name         = "example"
  address      = "*.example.mycompany.com"
  api_key_id   = banyan_api_key.example.name
  tunnel_cidrs = ["10.10.0.0/16"]
}

resource "banyan_service_tunnel" "users" {
  name         = "corporate network"
  description  = "tunnel allowing anyone with a high trust level access to 443"
  network_settings  {
    cluster      = "cluster1"
    access_tiers = [banyan_accesstier.example.name]
  }
  policy       = banyan_policy_tunnel.anyone-high.id
  polict_enforcing = true
}

resource "banyan_service_tunnel" "administrators" {
  name         = "corporate network admin"
  description  = "tunnel allowing administrators access to the networks"
  network_settings {
    cluster      = "cluster1"
    access_tiers = [banyan_accesstier.example.name]
  }
  policy       = banyan_policy_tunnel.administrators.id
}

resource "banyan_policy_tunnel" "anyone-high" {
  name        = "corporate-network-users"
  description = "${banyan_accesstier.example.name} allow users"
  access {
    roles       = ["Everyone"]
    trust_level = "High"
    l4_access {
      allow {
        cidrs     = ["10.10.10.0/24"]
        protocols = ["TCP"]
        ports     = ["443"]
      }
    }
  }
}

resource "banyan_policy_tunnel" "administrators" {
  name        = "corporate-network-admin"
  description = "${banyan_accesstier.example.name} allow only administrators access to the entire network"
  access {
    roles       = ["Everyone"]
    trust_level = "High"
    l4_access {
      allow {
        cidrs     = ["10.10.10.0/24"]
        protocols = ["TCP"]
        ports     = ["443"]
      }
    }
  }
}
```
In this example an access tier is configured to tunnel `10.10.0.0/16`. A service tunnel is configured to utilize this access tier, and a policy is attached which only allows users with a `High` trust level access to services running on port 443 in the subnet `10.10.1.0/24`. An additional service tunnel and policy allows administrators access to the entire network behind the tunnel.

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `name` (String) Name of the service tunnel
- `policy` (String) Policy ID to be attached to this service tunnel

### Optional

- `autorun` (Boolean) Autorun for the service, if set true service would autorun on the app
- `description` (String) Description of the service tunnel
- `description_link` (String) Link shown to the end user of the banyan app for this service
- `lock_autorun` (Boolean) Lock autorun for the service, if set true service tunnel will be always autorun. end user cannot set it off
- `name_resolution` (Block Set, Max: 1) Private Search Domains (see [below for nested schema](#nestedblock--name_resolution))
- `network_settings` (Block Set) Add a network that will be accessible via this Service Tunnel. (see [below for nested schema](#nestedblock--network_settings))
- `policy_enforcing` (Boolean) Policy Enforcing / Permissive

### Read-Only

- `id` (String) ID of the service tunnel key in Banyan

<a id="nestedblock--name_resolution"></a>
### Nested Schema for `name_resolution`

Optional:

- `dns_search_domains` (List of String)
- `name_servers` (List of String)


<a id="nestedblock--network_settings"></a>
### Nested Schema for `network_settings`

Optional:

- `access_tier_group` (String) AccessTier group name
- `access_tiers` (List of String)
- `applications` (Block Set, Max: 1) (see [below for nested schema](#nestedblock--network_settings--applications))
- `cluster` (String) cluster name where access-tier belongs to
- `connectors` (List of String)
- `public_cidrs` (Block Set, Max: 1) (see [below for nested schema](#nestedblock--network_settings--public_cidrs))
- `public_domains` (Block Set, Max: 1) (see [below for nested schema](#nestedblock--network_settings--public_domains))

<a id="nestedblock--network_settings--applications"></a>
### Nested Schema for `network_settings.applications`

Optional:

- `exclude` (List of String)
- `include` (List of String)


<a id="nestedblock--network_settings--public_cidrs"></a>
### Nested Schema for `network_settings.public_cidrs`

Optional:

- `exclude` (List of String)
- `include` (List of String)


<a id="nestedblock--network_settings--public_domains"></a>
### Nested Schema for `network_settings.public_domains`

Optional:

- `exclude` (List of String)
- `include` (List of String)
## Import
Import is supported using the following syntax:
```shell
# For importing a resource we require resource Id, which can be obtained from console for the resource we are importing
# And we need to create an entry in .tf file which represents the resource which would be imported.
# for e.g adding an entry into main.tf
# main.tf:
# resource "banyan_service_tunnel" "myexample" {
#   name = "myexample"
# }

terraform import banyan_service_tunnel.myexample 46f3a708-2a9a-4c87-b18e-b11b6c92bf24

terraform show
# update thw show output configuration into above main.tf file, then resource is managed.
# BE CAUTIOUS before terraform apply, do terraform plan and verify there are no changes to be applied.

# Terraform Version 1.5.x or Later:
# We can create Import tf files
# for e.g
# import.tf:
# import {
#  to = banyan_service_tunnel.myexample
#  id = "46f3a708-2a9a-4c87-b18e-b11b6c92bf24"
# }
#  Then execute
terraform plan -generate-config-out=generated.tf
# Configurations are imported into generated.tf edit and verify
# BE CAUTIOUS before terraform apply, do terraform plan and verify there are no changes to be applied.
```