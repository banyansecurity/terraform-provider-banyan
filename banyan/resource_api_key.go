package banyan

import (
	"context"
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/apikey"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceApiKey() *schema.Resource {
	return &schema.Resource{
		Description:   "The API key resource manages the lifecycle of API keys. API keys are used to provide authentication inside various permissions scopes. For more information on API keys see the [documentation](https://docs.banyansecurity.io/docs/banyan-components/command-center/api-keys/)",
		CreateContext: resourceApiKeyCreate,
		ReadContext:   resourceApiKeyRead,
		UpdateContext: resourceApiKeyUpdate,
		DeleteContext: resourceApiKeyDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the API key",
				ForceNew:    true,
			},
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the API key in Banyan",
				ForceNew:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Description of the API key",
			},
			"secret": {
				Type:        schema.TypeString,
				Description: "API Secret key",
				Sensitive:   true,
				Computed:    true,
				ForceNew:    true,
			},
			"scope": {
				Type:         schema.TypeString,
				Description:  "Scope for the API key. Must be one of: \"satellite\", \"access_tier\", \"read_logs\", \"Admin\", \"ServiceAuthor\", \"PolicyAuthor\", \"EventWriter\", \"ReadOnly\"",
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice([]string{"satellite", "access_tier", "read_logs", "Admin", "ServiceAuthor", "PolicyAuthor", "EventWriter", "ReadOnly"}, false),
			},
		},
	}
}

func resourceApiKeyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	key, err := c.ApiKey.Create(apikey.Post{
		Name:        d.Get("name").(string),
		Description: d.Get("description").(string),
		Scope:       d.Get("scope").(string),
	})
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("secret", key.Secret)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(key.ID)
	return
}

func resourceApiKeyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	_, err := c.ApiKey.Update(d.Id(), apikey.Post{
		Name:        d.Get("name").(string),
		Description: d.Get("description").(string),
		Scope:       d.Get("scope").(string),
	})
	if err != nil {
		return diag.FromErr(err)
	}
	return
}

func resourceApiKeyRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	key, err := c.ApiKey.Get(d.Id())
	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	d.SetId(key.ID)
	err = d.Set("name", key.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("description", key.Description)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("secret", key.Secret)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("scope", key.Scope)
	if err != nil {
		return diag.FromErr(err)
	}
	return
}

func resourceApiKeyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	err := c.ApiKey.Delete(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	d.SetId("")
	return
}
