# For importing a resource we require resource Id, which can be obtained from console for the resource we are importing
# And we need to create an entry in .tf file which represents the resource which would be imported.
# for e.g adding an entry into main.tf
# main.tf:
# resource "banyan_connector" "myexample" {
#   name = "myexample"
# }

terraform import banyan_connector.myexample 46f3a708-2a9a-4c87-b18e-b11b6c92bf24

terraform show
# update thw show output configuration into above main.tf file, then resource is managed.
# BE CAUTIOUS before terraform apply, do terraform plan and verify there are no changes to be applied.

# Terraform Version 1.5.x or Later:
# We can create Import tf files
# for e.g
# import.tf:
# import {
#  to = banyan_connector.myexample
#  id = "46f3a708-2a9a-4c87-b18e-b11b6c92bf24"
# }
#  Then execute
terraform plan -generate-config-out=generated.tf
# Configurations are imported into generated.tf edit and verify
# BE CAUTIOUS before terraform apply, do terraform plan and verify there are no changes to be applied.