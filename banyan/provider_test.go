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
	err := godotenv.Load("../.env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	testAccProvider = Provider()
	testAccProviders = map[string]*schema.Provider{
		"banyan": testAccProvider,
	}
	testAccClient, err = NewAccClient()
}

func NewAccClient() (c *client.ClientHolder, err error) {
	return client.NewClientHolder(os.Getenv("BANYAN_HOST"), os.Getenv("BANYAN_API_TOKEN"))
}

func TestProvider(t *testing.T) {
	if err := Provider().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestProvider_impl(t *testing.T) {
	var _ *schema.Provider = Provider()
}

func testAccPreCheck(t *testing.T) {
	err := godotenv.Load("../.env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	if err := os.Getenv("BANYAN_REFRESH_TOKEN"); err == "" {
		t.Fatal("BANYAN_REFRESH_TOKEN must be set for acceptance tests")
	}
	if err := os.Getenv("BANYAN_HOST"); err == "" {
		t.Fatal("BANYAN_HOST must be set for acceptance tests")
	}
}
