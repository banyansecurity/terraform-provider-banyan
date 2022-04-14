# banyan_role (Resource)

The banyan_role resource is used to manage roles in Banyan. A role represents a group of users in the organization. For more information see the documentation [here](https://docs.banyanops.com/docs/feature-guides/administer-security-policies/roles/manage-roles/).

### Example
```hcl
resource "banyan_role" "example" {
  name              = "some-role"
  description       = "some role description"
  user_group        = ["group1"]
  device_ownership  = ["Corporate Dedicated", "Corporate Shared", "Employee Owned", "Other"]
  platform          = ["Windows", "macOS", "Linux", "iOS", "Android", "Unregistered"]
}
```

### Required

- **description** (String) Description of the role
- **name** (String) Name of the role

### Optional

- **container_fqdn** (Set of String) FQDN for the container
- **device_ownership** (Set of String) Device ownership specification for the role
- **email** (Set of String) Email address for the user or group of users in the role
- **image** (Set of String) Image
- **known_device_only** (Boolean) Enforces whether the role requires known devices only for access
- **mdm_present** (Boolean) Enforces whether the role requires an MDM to be present on the device
- **platform** (Set of String) Platform type which is required by the role
- **repo_tag** (Set of String) Repo Tag
- **service_accounts** (Set of String) Service accounts to be included in the role
- **user_group** (Set of String) Name of the group (from your IdP) which will be included in the role

### Read-Only

- **id** (String) ID of the role in Banyan


