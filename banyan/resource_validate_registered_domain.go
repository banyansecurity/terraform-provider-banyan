package banyan

import (
	"context"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceValidateRegisteredDomain() *schema.Resource {
	return &schema.Resource{
		Description:   "Registered domain resource allows for configuration of the registered domain API object",
		CreateContext: resourceValidateRegisteredDomainCreate,

		// Skip Read, Update, and Delete by providing no-op functions
		ReadContext:   noOpRead,
		DeleteContext: noOpDelete,
		Schema:        ValidateRegisteredDomainSchema(),
	}
}

func ValidateRegisteredDomainSchema() map[string]*schema.Schema {
	s := map[string]*schema.Schema{
		"domain_id": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "registered domain id to validate",
			ForceNew:    true,
		},
	}

	return s
}

func resourceValidateRegisteredDomainCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostic diag.Diagnostics) {

	c := m.(*client.Holder)

	domainID := d.Get("domain_id").(string)

	_, err := c.RegisteredDomain.ValidateDomain(domainID)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(domainID)

	return
}

// No-op functions for Read, Update, and Delete
func noOpRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostic diag.Diagnostics) {
	return
}

func noOpDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostic diag.Diagnostics) {
	return nil
}
