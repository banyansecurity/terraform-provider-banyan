terraform {
  required_providers {
    banyan = {
      source  = "banyansecurity/banyan"
      version = "0.9.2"
    }
  }
}

provider "banyan" {
  api_key = "ADMIN_SCOPED_API_KEY"
}
