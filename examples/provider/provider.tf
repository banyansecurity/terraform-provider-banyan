terraform {
  required_providers {
    banyan = {
      source  = "banyansecurity/banyan"
      version = "1.1.0"
    }
  }
}

provider "banyan" {
  api_key = "BANYAN_API_KEY"
}
