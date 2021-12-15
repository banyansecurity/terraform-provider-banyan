package banyan

import (
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"log"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/joho/godotenv"
)

var testAccProviders map[string]*schema.Provider
var testAccProvider *schema.Provider
var testAccClient *client.ClientHolder

func init() {
	testAccPreCheck()
	testAccClient = NewAccClient()
	testAccProvider = Provider()
	testAccProviders = map[string]*schema.Provider{
		"banyan": testAccProvider,
	}

}

func NewAccClient() (c *client.ClientHolder) {
	c, err := client.NewClientHolder(os.Getenv("BANYAN_HOST"), os.Getenv("BANYAN_API_TOKEN"))
	if err != nil {
		log.Fatal("Could not create the test client")
	}
	return
}

func TestProvider(t *testing.T) {
	if err := Provider().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestProvider_impl(t *testing.T) {
	var _ *schema.Provider = Provider()
}

func testAccPreCheck() {
	err := godotenv.Load("../.env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	if err := os.Getenv("BANYAN_REFRESH_TOKEN"); err == "" {
		log.Fatal("BANYAN_REFRESH_TOKEN must be set for acceptance tests")
	}
	if err := os.Getenv("BANYAN_HOST"); err == "" {
		log.Fatal("BANYAN_HOST must be set for acceptance tests")
	}
}

func TestContains(t *testing.T) {
	if !Contains([]string{"foo", "bar"}, "bar") {
		t.Fatal("Element is in list but the function returned false")
	}
}
