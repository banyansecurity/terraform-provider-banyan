# banyan_connector

Used to create a Banyan Connector, which is a dial-out connector that establishes a secure tunnel with the Banyan Global Edge Network. For more information see the documentation [here](https://docs.banyansecurity.io/docs/banyan-components/connector/)

A connector requires an API key, which is also a resource which can be managed in Terraform. The following example shows a connector with an API key.

### Example
```hcl
resource "banyan_api_key" "example" {
  name        = "example-connector-api-key"
  description = "API key for example connector"
  scope       = "satellite"
}

resource "banyan_connector" "example" {
  name                 = "example-connector"
  satellite_api_key_id = resource.banyan_api_key.example.id
}
```

### Required

- **name** (String) Name of the connector
- **satellite_api_key_id** (String) ID of the connector in Banyan

### Optional

- **keepalive** (Number) ID of the connector in Banyan

### Read-Only

- **id** (String) ID of the connector in Banyan


