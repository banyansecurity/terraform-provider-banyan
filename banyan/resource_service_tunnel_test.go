package banyan

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/banyansecurity/terraform-banyan-provider/client/servicetunnel"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestSchemaServiceTunnel_tunnel_at(t *testing.T) {
	svc_tunnel_at := map[string]interface{}{
		"name":         "tunnel-at",
		"description":  "describe tunnel-at",
		"autorun":      true,
		"lock_autorun": true,
		"network_settings": []interface{}{
			map[string]interface{}{
				"cluster":      "cluster1",
				"access_tiers": []interface{}{"gcp-tdnovpn-v1"},
			},
		},
	}
	d := schema.TestResourceDataRaw(t, TunnelSchema(), svc_tunnel_at)
	svc_obj, _ := TunFromState(d)

	json_spec, _ := os.ReadFile("./specs/service_tunnel/tunnel-at.json")
	var ref_obj servicetunnel.Info
	_ = json.Unmarshal([]byte(json_spec), &ref_obj)

	AssertServiceTunnelEqual(t, svc_obj, ref_obj)
}

func TestSchemaServiceTunnel_tunnel_conn(t *testing.T) {
	svc_tunnel_conn := map[string]interface{}{
		"name":        "global-edge-tunnel",
		"description": "Geo DNS to multiple ATs",
		"network_settings": []interface{}{
			map[string]interface{}{
				"cluster":      "managed-cl-edge1",
				"access_tiers": []interface{}{"*"},
				"connectors":   []interface{}{"gcp-test-drive", "td-gcp-tdnovpn"},
			},
		},
	}
	d := schema.TestResourceDataRaw(t, TunnelSchema(), svc_tunnel_conn)
	svc_obj, _ := TunFromState(d)

	json_spec, _ := os.ReadFile("./specs/service_tunnel/tunnel-conn.json")
	var ref_obj servicetunnel.Info
	_ = json.Unmarshal([]byte(json_spec), &ref_obj)

	AssertServiceTunnelEqual(t, svc_obj, ref_obj)
}

func TestSchemaServiceTunnel_tunnel_public(t *testing.T) {
	svc_tunnel_public := map[string]interface{}{
		"name":        "tunnel-domains",
		"description": "describe tunnel-domains",
		"network_settings": []interface{}{
			map[string]interface{}{
				"cluster":      "cluster1",
				"access_tiers": []interface{}{"gcp-tdnovpn-v2"},
				"public_cidrs": []interface{}{
					map[string]interface{}{
						"include": []interface{}{"8.8.8.8/32", "75.75.75.75/32", "75.75.76.76/32"},
					},
				},
				"public_domains": []interface{}{
					map[string]interface{}{
						"include": []interface{}{"cnn.com", "icanhazip.com", "fast.com", "yahoo.com", "banyansecurity.io"},
					},
				},
				"applications": []interface{}{
					map[string]interface{}{
						"include": []interface{}{"067c3a25-8271-4764-89dd-c3543ac99a5a", "0b90e7d0-e8fc-43fb-95b7-4ad5d6881bb8"},
					},
				},
			},
		},
	}

	d := schema.TestResourceDataRaw(t, TunnelSchema(), svc_tunnel_public)
	svc_obj, _ := TunFromState(d)

	json_spec, _ := os.ReadFile("./specs/service_tunnel/tunnel-public.json")
	var ref_obj servicetunnel.Info
	_ = json.Unmarshal([]byte(json_spec), &ref_obj)

	AssertServiceTunnelEqual(t, svc_obj, ref_obj)
}

func TestSchemaServiceTunnel_tunnel_public_one_at(t *testing.T) {
	svc_tunnel_public := map[string]interface{}{
		"name":        "tunnel-domains",
		"description": "describe tunnel-domains",
		"network_settings": []interface{}{
			map[string]interface{}{
				"cluster":      "cluster1",
				"access_tiers": []interface{}{"gcp-tdnovpn-v2"},
				"public_cidrs": []interface{}{
					map[string]interface{}{
						"include": []interface{}{"8.8.8.8/32", "75.75.75.75/32", "75.75.76.76/32"},
					},
				},
				"public_domains": []interface{}{
					map[string]interface{}{
						"include": []interface{}{"cnn.com", "icanhazip.com", "fast.com", "yahoo.com", "banyansecurity.io"},
					},
				},
				"applications": []interface{}{
					map[string]interface{}{
						"include": []interface{}{"067c3a25-8271-4764-89dd-c3543ac99a5a", "0b90e7d0-e8fc-43fb-95b7-4ad5d6881bb8"},
					},
				},
			},
		},
	}
	d := schema.TestResourceDataRaw(t, TunnelSchema(), svc_tunnel_public)
	svc_obj, _ := TunFromState(d)

	json_spec, _ := os.ReadFile("./specs/service_tunnel/tunnel-public.json")
	var ref_obj servicetunnel.Info
	_ = json.Unmarshal([]byte(json_spec), &ref_obj)

	AssertServiceTunnelEqual(t, svc_obj, ref_obj)
}

func TestSchemaServiceTunnel_tunnel_public_select_at_from_multiple(t *testing.T) {
	svc_tunnel_public := map[string]interface{}{
		"name":        "tunnel-domains",
		"description": "describe tunnel-domains",
		"network_settings": []interface{}{
			map[string]interface{}{
				"cluster":      "cluster1",
				"access_tiers": []interface{}{"gcp-tdnovpn-v2"},
				"public_cidrs": []interface{}{
					map[string]interface{}{
						"include": []interface{}{"8.8.8.8/32", "75.75.75.75/32", "75.75.76.76/32"},
					},
				},
				"public_domains": []interface{}{
					map[string]interface{}{
						"include": []interface{}{"cnn.com", "icanhazip.com", "fast.com", "yahoo.com", "banyansecurity.io"},
					},
				},
				"applications": []interface{}{
					map[string]interface{}{
						"include": []interface{}{"067c3a25-8271-4764-89dd-c3543ac99a5a", "0b90e7d0-e8fc-43fb-95b7-4ad5d6881bb8"},
					},
				},
			},
		},
	}
	d := schema.TestResourceDataRaw(t, TunnelSchema(), svc_tunnel_public)
	svc_obj, _ := TunFromState(d)

	json_spec, _ := os.ReadFile("./specs/service_tunnel/tunnel-public-multiple-at.json")
	var ref_obj servicetunnel.Info
	_ = json.Unmarshal([]byte(json_spec), &ref_obj)

	AssertServiceTunnelEqual(t, svc_obj, ref_obj)
}

// Use the terraform plugin sdk testing framework for example testing servicetunnel lifecycle
func TestAccServiceTunnel_basic(t *testing.T) {

	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: nil,
		Steps: []resource.TestStep{
			// Creates the servicetunnel with the given terraform configuration and asserts that the servicetunnel is created
			{
				Config: fmt.Sprintf(`
					resource "banyan_api_key" "example" {
						name              = "%s"
						description       = "realdescription"
						scope             = "access_tier"
					}

					resource banyan_accesstier "example" {
						name = "%s"
						address = "*.example.com"
						api_key_id = banyan_api_key.example.id
					}

					resource "banyan_policy_tunnel" "example" {
						name        = "%s"
						description = "some tunnel policy description"
						access {
							roles       = ["ANY"]
							trust_level = "High"
						}
					}

					resource "banyan_service_tunnel" "example" {
						name              = "%s"
						description       = "realdescription"
                        network_settings {
							cluster = "cluster1"
							access_tiers = [banyan_accesstier.example.name]
						}
						policy            = banyan_policy_tunnel.example.id
						policy_enforcing  = false
					}
					`, rName, rName, rName, rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("banyan_service_tunnel.example", "name", rName),
				),
			},
			{
				ResourceName:      "banyan_service_tunnel.example",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: fmt.Sprintf(`
					resource "banyan_api_key" "example" {
						name              = "%s"
						description       = "realdescription"
						scope             = "access_tier"
					}

					resource banyan_accesstier "example" {
						name = "%s"
						address = "*.example.com"
						api_key_id = banyan_api_key.example.id
					}

					resource "banyan_policy_tunnel" "example" {
						name        = "%s"
						description = "some tunnel policy description"
						access {
							roles       = ["ANY"]
							trust_level = "High"
						}
					}

					resource "banyan_service_tunnel" "example" {
						name              = "%s"
						description       = "some description"
                        network_settings {
							cluster = "cluster1"
							access_tiers = [banyan_accesstier.example.name]
						}
						policy            = banyan_policy_tunnel.example.id
					}
					`, rName, rName, rName, rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("banyan_service_tunnel.example", "name", rName),
				),
			},
			{
				ResourceName:      "banyan_service_tunnel.example",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccServiceTunnel_change_policy(t *testing.T) {

	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: nil,
		Steps: []resource.TestStep{
			// Creates the servicetunnel with the given terraform configuration and asserts that the servicetunnel is created
			{
				Config: fmt.Sprintf(`
					resource "banyan_api_key" "example" {
						name              = "%s"
						description       = "realdescription"
						scope             = "access_tier"
					}

					resource banyan_accesstier "example" {
						name = "%s"
						address = "*.example.com"
						api_key_id = banyan_api_key.example.id
					}

					resource "banyan_policy_tunnel" "example" {
						name        = "%s"
						description = "some tunnel policy description"
						access {
							roles       = ["ANY"]
							trust_level = "High"
						}
					}

					resource "banyan_service_tunnel" "example" {
						name              = "%s"
						description       = "realdescription"
						network_settings {
							cluster 		  = "cluster1"
							access_tiers      = [banyan_accesstier.example.name]
						}                        
						policy            = banyan_policy_tunnel.example.id
					}
					`, rName, rName, rName, rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("banyan_service_tunnel.example", "name", rName),
				),
			},
			{
				Config: fmt.Sprintf(`
					resource "banyan_api_key" "example" {
						name              = "%s"
						description       = "realdescription"
						scope             = "access_tier"
					}

					resource banyan_accesstier "example" {
						name = "%s"
						address = "*.example.com"
						api_key_id = banyan_api_key.example.id
					}

					resource "banyan_policy_tunnel" "example" {
						name        = "%s"
						description = "some tunnel policy description"
						access {
							roles       = ["ANY"]
							trust_level = "High"
						}
					}

					resource "banyan_policy_tunnel" "new" {
						name        = "%s-new"
						description = "some tunnel policy description"
						access {
							roles       = ["ANY"]
							trust_level = "Low"
						}
					}

					resource "banyan_service_tunnel" "example" {
						name              = "%s"
						description       = "some description"
						network_settings {
							cluster 		  = "cluster1"
							access_tiers      = [banyan_accesstier.example.name]
						}    
						policy            = banyan_policy_tunnel.new.id
					}
					`, rName, rName, rName, rName, rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("banyan_service_tunnel.example", "name", rName),
				),
			},
		},
	})
}

func TestSchemaServiceTunnel_with_access_tier_group(t *testing.T) {
	svc_tunnel_public := map[string]interface{}{
		"name":        "tunnel-domains",
		"description": "describe tunnel-domains",
		"network_settings": []interface{}{
			map[string]interface{}{
				"cluster":           "cluster1",
				"access_tier_group": "atg-1",
			},
		},
	}
	d := schema.TestResourceDataRaw(t, TunnelSchema(), svc_tunnel_public)
	svc_obj, _ := TunFromState(d)

	json_spec := []byte(`{
		"kind": "BanyanServiceTunnel",
		"api_version": "rbac.banyanops.com/v1",
		"type": "origin",
		"metadata":
		{
			"name": "tunnel-domains",
			"friendly_name": "tunnel-domains",
			"description": "describe tunnel-domains",
			"tags":
			{
				"icon": "",
				"description_link": ""
			},
      "autorun": false,
      "lock_autorun": false
		},
		"spec":
		{
			"peer_access_tiers":
			[
				{
					"cluster": "cluster1",
					"access_tier_group":"atg-1"
				}
			]
		}
	}`)
	var ref_obj servicetunnel.Info
	_ = json.Unmarshal([]byte(json_spec), &ref_obj)

	AssertServiceTunnelEqual(t, svc_obj, ref_obj)
}

func TestAccServiceTunnel_with_access_tier_group(t *testing.T) {

	rName := fmt.Sprintf("tf-acc-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))

	resource.Test(t, resource.TestCase{
		Providers:    testAccProviders,
		CheckDestroy: nil,
		Steps: []resource.TestStep{
			// Creates the servicetunnel with the given terraform configuration and asserts that the servicetunnel is created
			{
				Config: fmt.Sprintf(`

					resource "banyan_policy_tunnel" "example" {
						name        = "%s"
						description = "some tunnel policy description"
						access {
							roles       = ["ANY"]
							trust_level = "High"
						}
					}

					resource "banyan_service_tunnel" "example" {
						name                    = "%s"
						description       	    = "realdescription"
						network_settings {
   							cluster 				= "cluster1"
							access_tier_group       = "new-grp-1"
                        }
						policy                  = banyan_policy_tunnel.example.id
					}
					`, rName, rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("banyan_service_tunnel.example", "name", rName),
				),
			},
			{
				ResourceName:      "banyan_service_tunnel.example",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}
