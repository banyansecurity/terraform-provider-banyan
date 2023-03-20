package banyan

import (
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"log"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var testAccProviders map[string]*schema.Provider
var testAccProvider *schema.Provider
var testAccClient *client.Holder

func init() {
	testAccPreCheck()
	testAccClient = NewAccClient()
	testAccProvider = Provider()
	testAccProviders = map[string]*schema.Provider{
		"banyan": testAccProvider,
	}
}

func NewAccClient() (c *client.Holder) {
	c, err := client.NewClientHolder(client.GetBanyanHostUrl(), client.GetApiKey())
	if err != nil {
		log.Fatal("Could not create the test client")
	}
	return
}

func TestProvider(t *testing.T) {
	if err := Provider().InternalValidate(); err != nil {
		t.Fatal(err)
	}
}

func TestProvider_impl(t *testing.T) {
	var _ *schema.Provider = Provider()
}

func testAccPreCheck() {
	if err := client.GetApiKey(); err == "" {
		log.Fatal("BANYAN_API_KEY must be set for acceptance tests")
	}
	if err := client.GetBanyanHostUrl(); err == "" {
		log.Fatal("BANYAN_HOST must be set for acceptance tests")
	}
}
