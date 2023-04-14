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
		"cluster":      "cluster1",
		"access_tiers": []interface{}{"gcp-tdnovpn-v1", "gcp-tdnovpn-v2"},
	}
	d := schema.TestResourceDataRaw(t, TunnelSchema(), svc_tunnel_at)
	svc_obj := TunFromState(d)

	json_spec, _ := os.ReadFile("./specs/service_tunnel/tunnel-at.json")
	var ref_obj servicetunnel.Info
	_ = json.Unmarshal([]byte(json_spec), &ref_obj)

	AssertServiceTunnelEqual(t, svc_obj, ref_obj)
}

func TestSchemaServiceTunnel_tunnel_conn(t *testing.T) {
	svc_tunnel_conn := map[string]interface{}{
		"name":        "global-edge-tunnel",
		"description": "Geo DNS to multiple ATs",
		"cluster":     "managed-cl-edge1",
		"connectors":  []interface{}{"gcp-test-drive", "td-gcp-tdnovpn"},
	}
	d := schema.TestResourceDataRaw(t, TunnelSchema(), svc_tunnel_conn)
	svc_obj := TunFromState(d)

	json_spec, _ := os.ReadFile("./specs/service_tunnel/tunnel-conn.json")
	var ref_obj servicetunnel.Info
	_ = json.Unmarshal([]byte(json_spec), &ref_obj)

	AssertServiceTunnelEqual(t, svc_obj, ref_obj)
}

func TestSchemaServiceTunnel_tunnel_public(t *testing.T) {
	svc_tunnel_public := map[string]interface{}{
		"name":                   "tunnel-domains",
		"description":            "describe tunnel-domains",
		"cluster":                "cluster1",
		"access_tiers":           []interface{}{"gcp-tdnovpn-v2"},
		"public_cidrs_include":   []interface{}{"8.8.8.8/32", "75.75.75.75/32", "75.75.76.76/32"},
		"public_domains_include": []interface{}{"cnn.com", "icanhazip.com", "fast.com", "yahoo.com", "banyansecurity.io"},
	}
	d := schema.TestResourceDataRaw(t, TunnelSchema(), svc_tunnel_public)
	svc_obj := TunFromState(d)

	json_spec, _ := os.ReadFile("./specs/service_tunnel/tunnel-public.json")
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
						access_tiers      = [banyan_accesstier.example.name]
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
						access_tiers      = [banyan_accesstier.example.name]
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
						access_tiers      = [banyan_accesstier.example.name]
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
						access_tiers      = [banyan_accesstier.example.name]
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
