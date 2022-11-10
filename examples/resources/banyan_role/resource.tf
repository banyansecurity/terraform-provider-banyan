resource "banyan_role" "example" {
  name             = "example"
  description      = "some role description"
  user_group       = ["name-of-group"]
  device_ownership = ["Corporate Dedicated", "Corporate Shared", "Employee Owned", "Other"]
  platform         = ["Windows", "macOS", "Linux", "iOS", "Android", "Unregistered"]
}