# banyan_policy

Banyan policies control access to a service. For more information on Banyan policies, see the [documentation](https://docs.banyanops.com/docs/feature-guides/administer-security-policies/policies/manage-policies/).

### Example Web Policy
```hcl
resource "banyan_policy" "example" {
	name        = "web-policy"
	description = "some web policy description"
	access {
		roles       = ["Everyone"]
		trust_level = "High"
		l7_access {
			resources = ["*"]
			actions   = ["*"]
		}
	}
	l7_protocol                       = "http"
	disable_tls_client_authentication = true
}
```

### Required

- **access** (Block List, Min: 1) Access describes the access rights for a set of roles (see [below for nested schema](#nestedblock--access))
- **description** (String) Description of the policy
- **name** (String) Name of the policy

### Optional

- **disable_tls_client_authentication** (Boolean) Prevents the service from asking for a client TLS cert
- **l7_protocol** (String) L7Protocol specifies the application-level protocol: "http", "kafka", or empty string.
					If L7Protocol is not empty, then all Access rules must have L7Access entries.

### Read-Only

- **id** (String) ID of the policy in Banyan

<a id="nestedblock--access"></a>
### Nested Schema for `access`

Required:

- **roles** (Set of String) Roles that all have the access rights given by rules
- **trust_level** (String) The trust level of the end user device, must be one of: "High", "Medium", "Low", or ""

Optional:

- **l7_access** (Block List) Specifies a set of access rights to application level (OSI Layer-7) resources. (see [below for nested schema](#nestedblock--access--l7_access))

<a id="nestedblock--access--l7_access"></a>
### Nested Schema for `access.l7_access`

Required:

- **actions** (Set of String) Actions are a list of application-level actions: "READ", "WRITE", "CREATE", "UPDATE", "*"
- **resources** (Set of String) Resources are a list of application level resources.
														Each resource can have wildcard prefix or suffix, or both.
														A resource can be prefixed with "!", meaning DENY.
														Any DENY rule overrides any other rule that would allow the access.