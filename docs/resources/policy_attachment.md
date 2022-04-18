# banyan_policy_attachment

A Banyan policy attachment attaches a policy to a service.

Typically, this resource is used in conjunction with a service and a policy. The following example shows a policy, a service, and a policy attachment referencing each other.

### Example
```hcl
resource "banyan_policy_attachment" "example" {
  policy_id        = banyan_policy.some-policy.id
  attached_to_type = "service"
  attached_to_id   = banyan_service.some-service.id
}
```

### Required

- **attached_to_id** (String) ID of the resource the policy will be attached to
- **attached_to_type** (String) Type which the policy is attached to (i.e. service / saasapp)
- **policy_id** (String) Name of the policy

### Optional

- **id** (String) The ID of this resource.
- **is_enforcing** (Boolean) Sets whether the policy is enforcing or not
