# banyan_connector (Resource)

Used to create a Banyan Connector, which is a dial-out connector that establishes a secure tunnel with the Banyan Global Edge Network.

### Example
```hcl
resource "banyan_connector" "example" {
  name                 = "connector-vpc1"
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


