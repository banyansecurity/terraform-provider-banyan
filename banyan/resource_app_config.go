package banyan

import (
	"context"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/appconfig"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceAppConfig() *schema.Resource {
	return &schema.Resource{
		Description:   "The app config resource allows for creating and updating configuration of app for an org. ",
		CreateContext: resourceAppConfigCreate,
		ReadContext:   resourceAppConfigRead,
		UpdateContext: resourceAppConfigUpdate,
		DeleteContext: resourceAppConfigDelete,
		Schema: AppConfigSchema(),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
	}
}

func AppConfigSchema() map[string]*schema.Schema {
	s := map[string]*schema.Schema{
		"id": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "ID of the app config in Banyan",
			ForceNew:    true,
		},
		"nrpt_config": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Enable/Disable nrpt config for app",
		},
	}
	return s
}

func resourceAppConfigCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	atg, err := c.AppConfig.Create(appConfigFromState(d))
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(atg.ID)

	return
}

func resourceAppConfigRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	key, err := c.AppConfig.Get(d.Id())
	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	d.SetId(key.ID)
	err = d.Set("nrpt_config", key.NRPTConfig)
	if err != nil {
		return diag.FromErr(err)
	}

	return
}

func resourceAppConfigUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	_, err := c.AppConfig.Update(appConfigFromState(d))
	if err != nil {
		return diag.FromErr(err)
	}

	return
}

func resourceAppConfigDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	err := c.AppConfig.Delete(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	d.SetId("")
	return
}

// creates an app config from the terraform state
func appConfigFromState(d *schema.ResourceData) appconfig.AppConfigRequest {
	nrptConfig := d.Get("nrpt_config").(bool)
	ac := appconfig.AppConfigRequest{
		NRPTConfig: &nrptConfig,
	}
	return ac
}
