# banyan_policy_web

Resource for lifecycle management of web policies. For more information on Banyan policies, see the [documentation.](https://docs.banyanops.com/docs/feature-guides/administer-security-policies/policies/manage-policies/)

### Example
```hcl
resource "banyan_policy_web" "example" {
  name        = "example"
  description = "some web policy description"
  access {
    roles       = ["ANY"]
    trust_level = "High"
  }
}
```

### Example Layer 7 Policy
```hcl
resource "banyan_policy_web" "example" {
  name        = "example"
  description = "some web policy description"
  access {
    roles       = ["Admin"]
    trust_level = "High"
    l7_resources = ["/admin"]
    l7_actions   = ["READ"]
  }
}
```

### Required

- **access** (Block List, Min: 1) Access describes the access rights for a set of roles (see [below for nested schema](#nestedblock--access))
- **description** (String) Description of the policy
- **name** (String) Name of the policy

### Read-Only

- **id** (String) ID of the policy in Banyan

<a id="nestedblock--access"></a>
### Nested Schema for `access`

Required:

- **roles** (Set of String) Roles that all have the access rights given by rules
- **trust_level** (String) The trust level of the end user device, must be one of: "High", "Medium", "Low", or ""

Optional:

- **l7_actions** (Set of String) Actions are a list of application-level actions: "CREATE", "READ", "UPDATE", "DELETE", "*"
- **l7_resources** (Set of String) Resources are a list of application level resources.
								Each resource can have wildcard prefix or suffix, or both.
								A resource can be prefixed with "!", meaning DENY.
								Any DENY rule overrides any other rule that would allow the access.


