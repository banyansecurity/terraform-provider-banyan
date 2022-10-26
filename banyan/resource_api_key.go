package banyan

import (
	"context"
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/apikey"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceApiKey() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages API keys",
		CreateContext: resourceApiKeyCreate,
		ReadContext:   resourceApiKeyRead,
		UpdateContext: resourceApiKeyUpdate,
		DeleteContext: resourceApiKeyDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the API key",
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
				Computed:    true,
				Sensitive:   true,
				ForceNew:    true,
			},
			"scope": {
				Type:        schema.TypeString,
				Description: "API Secret key",
				Optional:    true,
				ForceNew:    true,
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
	d.SetId(key.ID)
	diagnostics = resourceApiKeyRead(ctx, d, m)
	return
}

func resourceApiKeyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	return resourceApiKeyCreate(ctx, d, m)
}

func resourceApiKeyRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	key, err := c.ApiKey.Get(d.Id())
	if err != nil {
		return diag.FromErr(err)
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
