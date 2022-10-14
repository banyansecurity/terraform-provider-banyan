
# Banyan terraform provider

This module contains all the Terraform resources supported by the Banyan Terraform Provider.

## Testing
This project uses the Terraform plugin SDK testing framework for testing that the resource lifecycle can be managed by terraform.

Each resource, at a minimum, must hava a `required` and `optional` test. 
The required test checks that a resource with only the required parameters set can be created properly
The optional test checks that a resource with all of the required and optional parameters can be created properly.
An edge case test with a different name would be used to test a specific configuration which cannot be covered by the required and optional test.
