---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "banyan_accesstier_group Resource - terraform-provider-banyan"
subcategory: ""
description: |-
  The access tier group resource allows for configuration of the access tier group API object.
---

# banyan_accesstier_group (Resource)

The access tier group resource allows for configuration of the access tier group API object.



<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `advanced_settings` (String) Advanced settings
- `cidrs` (Set of String) CIDR range
- `cluster` (String) Cluster / shield name in Banyan
- `dns_search_domains` (String)
- `domains` (Set of String) Any internal domains that can only be resolved on your internal network’s private DNS
- `keepalive` (Number) Keepalive
- `name` (String) Name of the access tier group
- `shared_fqdn` (String) Shared FQDN
- `udp_port_number` (Number) UDP port

### Optional

- `attach_access_tier_ids` (Set of String) Access tier IDs to attach to access tier group
- `description` (String) Description of access tier group
- `detach_access_tier_ids` (Set of String) Access tier IDs to detach from access tier group
- `dns_enabled` (Boolean) Enable DNS for service tunnels (needed to work properly with both private and public targets)

### Read-Only

- `id` (String) ID of the access tier group in Banyan