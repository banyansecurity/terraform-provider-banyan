# Banyan Terraform Provider
### Currently in Beta

Banyan replaces your traditional network access boxes – VPNs, bastion hosts, and gateways – with a cloud-based zero trust access solution.

The Banyan Terraform provider is used for lifecycle management of Banyan resources including roles, policies, and services. Learn more about Banyan [here.](https://www.banyansecurity.io/)

Use the navigation to the left to read about the available resources.

To learn the basics of the Banyan components, check out the documentation [here.](https://docs.banyanops.com/)

### Known Issues
* Required fields for resources may not match the UI exactly
* Some fields missing descriptions
* Some defaults for fields have not yet been implemented

### Security Best Practices
Ensure to create a Banyan API token exclusive to Terraform. This will ensure that all actions taken by Terraform automation will appear in the console logs with the API key as the actor.

For production use cases, ensure that the API token is stored in an environment variable and inject it into Terraform as such:
```hcl
provider "banyan" {
  api_token = "banyan-api-token-here-exclusive-to-terraform"
}
```

### Note About **Preview** Organizations
Ensure that the `host` parameter is set to the correct host:
```hcl
provider "banyan" {
  api_token = "banyan-api-token-here-exclusive-to-terraform"
  host = "https://preview.console.banyanops.com/"
}
```

## Example Provider Configuration
```hcl
terraform {
  required_providers {
    banyan = {
      source = "banyansecurity/banyan"
      version = "0.6.3"
    }
  }
}

provider "banyan" {
  api_token = "banyan-api-token-here-exclusive-to-terraform"
}
```

## Example configured provider with a service, role, policy, and policy attachment

In this example we import the Banyan Terraform provider, and configure it with an admin API key. Then we create a service for a sensitive admin console, and attach an admin role with a strict admin policy to restrict access to only authorized administrators on trusted devices.
```hcl
provider "banyan" {
  api_token = var.banyan_refresh_token
  host      = var.banyan_host
}

resource "banyan_service_web" "admin-console" {
  name           = "admin-console"
  description    = "Super sensitive admin console"
  cluster        = "us-west"
  access_tier    = "us-west1"
  domain         = "admin-console.corp.com"
  protocol       = "https"
  port           = 443
  backend_domain = "example-web.internal"
  backend_port   = 8443
  backend_tls    = true
}

resource "banyan_policy" "admin-web-high" {
  name        = "web-policy"
  description = "Allows web access to admins with a high trust level"
  access {
    roles       = [banyan_role.admin.name]
    trust_level = "High"
    l7_access {
      resources = ["*"]
      actions   = ["*"]
    }
  }
  l7_protocol                       = "http"
  disable_tls_client_authentication = true
}

resource "banyan_role" "admin" {
  name              = "admin"
  description       = "Strict role for Admin access"
  user_group        = ["admin"]
  device_ownership  = ["Corporate Dedicated"]
  known_device_only = true
  mdm_present       = true
  platform          = ["Windows", "macOS", "Linux"]
}

resource "banyan_policy_attachment" "example-high-trust-any" {
  policy_id        = banyan_policy.admin-web-high.id
  attached_to_type = "service"
  attached_to_id   = banyan_service_web.admin-console.id
}
```

## Schema

### Required

- **api_token** (String) The Banyan Terraform Provider requires an API token

### Optional

- **host** (String) The host parameter is used to point the Banyan Terraform Provider to a non-default url 