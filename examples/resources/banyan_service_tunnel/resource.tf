resource "banyan_api_key" "example" {
  name        = "example api key"
  description = "example api key"
  scope       = "access_tier"
}

resource "banyan_accesstier" "example" {
  name         = "example"
  address      = "*.example.mycompany.com"
  api_key_id   = banyan_api_key.example.name
  tunnel_cidrs = ["10.10.1.0/24"]
}

resource "banyan_service_tunnel" "example" {
  name         = "example-anyone-high"
  description  = "tunnel allowing anyone with a high trust level"
  network_settings {
    cluster      = "cluster1"
    access_tiers = [banyan_accesstier.example.name]
  }
  policy       = banyan_policy_tunnel.anyone-high.id
  policy_enforcing = true
}

resource "banyan_service_tunnel" "example1" {
  name         = "example-anyone-high"
  description  = "tunnel allowing anyone with a high trust level"
  network_settings {
    cluster      = "cluster1"
    access_tiers = [banyan_accesstier.example.name]
  }
  network_settings {
    connectors = ["myconnector"]
    public_cidrs {
      include = ["8.8.8.8/32", "75.75.75.75/32", "75.75.76.76/32"]
      exclude = ["99.99.99.99/32"]
    }
    public_domains {
      include = ["cnn.com", "icanhazip.com", "fast.com", "yahoo.com", "banyansecurity.io"]
      exclude = ["excluded.com"]
    }
    applications {
      include = ["067c3a25-8271-4764-89dd-c3543ac99a5a", "0b90e7d0-e8fc-43fb-95b7-4ad5d6881bb8"]
      exclude = ["067c3a25-8271-4764-89dd-c3543ac99a5c"]
    }
  }
  network_settings {
    cluster = "cluster1"
    access_tiers = ["myaccesstier1"]
    public_cidrs {
      include = ["8.8.8.8/32", "75.75.75.75/32", "75.75.76.76/32"]
      exclude = ["99.99.99.99/32"]
    }
    public_domains {
      include = ["cnn.com", "icanhazip.com", "fast.com", "yahoo.com", "banyansecurity.io"]
      exclude = ["excluded.com"]
    }
    applications {
      include = ["067c3a25-8271-4764-89dd-c3543ac99a5a", "0b90e7d0-e8fc-43fb-95b7-4ad5d6881bb8"]
      exclude = ["067c3a25-8271-4764-89dd-c3543ac99a5c"]
    }
  }

  network_settings {
    cluster = "cluster1"
    access_tier_group = "atg"
    public_cidrs {
      include = ["8.8.8.8/32", "75.75.75.75/32", "75.75.76.76/32"]
      exclude = ["99.99.99.99/32"]
    }
    public_domains {
      include = ["cnn.com", "icanhazip.com", "fast.com", "yahoo.com", "banyansecurity.io"]
      exclude = ["excluded.com"]
    }
    applications {
      include = ["067c3a25-8271-4764-89dd-c3543ac99a5a", "0b90e7d0-e8fc-43fb-95b7-4ad5d6881bb8"]
      exclude = ["067c3a25-8271-4764-89dd-c3543ac99a5c"]
    }
  }
  name_resolution {
    name_servers = ["8.8.8.8"]
    dns_search_domains = ["mylocal.local"]
  }
  policy       = banyan_policy_tunnel.anyone-high.id
  policy_enforcing = true
}



resource "banyan_policy_tunnel" "anyone-high" {
  name        = "allow anyone"
  description = "${banyan_accesstier.example.name} allow"
  access {
    roles       = ["ANY"]
    trust_level = "High"
  }
}