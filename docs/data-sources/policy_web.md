---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "banyan_policy_web Data Source - terraform-provider-banyan"
subcategory: ""
description: |-
  Obtains information describing the web policy from banyan
---

# banyan_policy_web (Data Source)

Obtains information describing the web policy from banyan

## Example Usage

```terraform
data "banyan_policy_web" "example" {
    name = "my-example-policy"
}

resource "banyan_service_web" "example" {
  name           = "example-web"
  access_tier    = "us-west1"
  domain         = "example-web.us-west1.mycompany.com"
  backend_domain = "example-web.internal"
  backend_port   = 8443
  policy         = data.banyan_policy_web.example.id
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `name` (String) Name of the policy

### Read-Only

- `access` (List of Object) Access describes the access rights for a set of roles (see [below for nested schema](#nestedatt--access))
- `description` (String) Description of the policy
- `id` (String) ID of the policy in Banyan

<a id="nestedatt--access"></a>
### Nested Schema for `access`

Read-Only:

- `l7_access` (List of Object) (see [below for nested schema](#nestedobjatt--access--l7_access))
- `roles` (Set of String)
- `trust_level` (String)

<a id="nestedobjatt--access--l7_access"></a>
### Nested Schema for `access.l7_access`

Read-Only:

- `actions` (Set of String)
- `resources` (Set of String)