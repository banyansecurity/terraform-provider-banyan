# banyan_api_key

Resource used for lifecycle management of API keys. For more information see the documentation [here](https://docs.banyansecurity.io/docs/banyan-components/command-center/api-keys/)

### Example
```hcl
resource "banyan_api_key" "example" {
  name        = "example-connector-api-key"
  description = "API key for example connector"
  scope       = "satellite"
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


