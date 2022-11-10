terraform {
  required_providers {
    banyan = {
      source  = "github.com/banyansecurity/banyan"
      version = ">=0.9.0"
    }
  }
}

provider "banyan" {
  api_key = "DAM-sKTrYSgkG9BI1o0KO1mI0hbRrda33_sEcgOCa9Y"
  host = "https://dev06.console.bnntest.com"
}

resource "banyan_api_key" "example" {
  name        = "my-connector"
  description = "realdescription"
  scope       = "satellite"
}

resource "banyan_connector" "example" {
  name    = "my-connector"
  api_key = banyan_api_key.example.name
  domains = ["my-connector.mycompany.com"]
}