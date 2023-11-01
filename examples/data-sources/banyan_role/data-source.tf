data "banyan_role" "example" {
    name = "my-example-policy"
    description = "realdescription"
    container_fqdn = ["asdf.asdf"]
    known_device_only = true
    platform = ["macOS", "Android"]
    user_group = ["group1", "group2"]
    email = ["john@marsha.com"]
    device_ownership = ["Corporate Dedicated", "Employee Owned"]
    mdm_present = true
   serial_numbers = ["DeviceSerial1"]
}

resource "banyan_service_web" "example" {
  name = "example-infra-service"
  policy = data.banyan_policy_infra.example.id
  
}