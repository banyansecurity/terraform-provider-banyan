# banyan_api_key (Resource)

Manages API keys

### Example
```hcl
resource "banyan_api_key" "example" {
  name              = "%s"
  description       = "some description"
  scope             = "satellite"
}
```

### Required

- **description** (String) Description of the API key
- **name** (String) Name of the API key

### Optional

- **scope** (String) API key scope i.e. `satellite` `admin`

### Read-Only

- **id** (String) ID of the API key in Banyan
- **secret** (String, Sensitive) API Secret key


