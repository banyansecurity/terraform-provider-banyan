# banyan_policy_infra

Resource for lifecycle management of infrastructure policies. For more information on Banyan policies, see the [documentation.](https://docs.banyanops.com/docs/feature-guides/administer-security-policies/policies/manage-policies/)

### Example
```hcl
resource "banyan_policy_infra" "example" {
  name        = "example"
  description = "some infrastructure policy description"
  access {
    roles       = ["ANY"]
    trust_level = "High"
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
