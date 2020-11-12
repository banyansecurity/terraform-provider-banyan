terraform {
  required_providers {
    banyan = {
      versions = ["0.1.0"]
      source = "github.com/banyansecurity/banyan"
    }
    okta = {
       source = "oktadeveloper/okta" 
       version = "~> 3.6"
    }
  }
}

provider "okta" {
    org_name = var.okta_org_name
    base_url = "okta.com"
    api_token = var.okta_api_token
}

provider "banyan" {
    refresh_token = var.banyan_refresh_token
    host = var.banyan_host
}

data "banyan_oidc_settings" "my-urls" {}
data "okta_everyone_group" "everyone" {}

output "oidc_redirect_url" {
    value = data.banyan_oidc_settings.my-urls.authorization_endpoint
}

resource "banyan_org_idp_config" "my-idp-config" {
    idp_name = "OKTA"
    idp_protocol = "OIDC"
    idp_config {
        issuer_url = "http://${var.okta_org_name}.okta.com"
        client_secret = okta_app_oauth.banyan-trustprovider.client_secret
        client_id = okta_app_oauth.banyan-trustprovider.client_id
    }
}

resource "okta_app_oauth" "banyan-trustprovider" {
    label = "terraform banyan trust provider"
    grant_types = ["authorization_code"]
    type = "web"
    redirect_uris = [data.banyan_oidc_settings.my-urls.redirect_url]
    hide_web = true

    lifecycle {
        ignore_changes = [groups]
    }
    // need to find way to setup groups claim currently an "internal" api could make our own provider for that...
}

resource "okta_app_group_assignment" "banyan-trustprovider-everyone-group" {
    app_id = okta_app_oauth.banyan-trustprovider.id
    group_id = data.okta_everyone_group.everyone.id
}
