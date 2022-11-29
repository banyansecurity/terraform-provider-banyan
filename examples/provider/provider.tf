terraform {
  required_providers {
    banyan = {
      source  = "banyansecurity/banyan"
      version = "1.0"
    }
  }
}

provider "banyan" {
  api_key = "ADMIN_SCOPED_API_KEY"
}
