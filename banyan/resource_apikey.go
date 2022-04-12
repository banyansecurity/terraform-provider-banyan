package banyan

import (
	"context"
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/apikey"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
	"log"
)

// Schema for the apikey resource. For more information on Banyan policies, see the documentation:
func resourceApiKey() *schema.Resource {
	log.Println("[APIKEY|RES] getting resource schema")
	return &schema.Resource{
		Description:   "Banyan policies control access to a service. For more information on Banyan policies, see the [documentation.](https://docs.banyanops.com/docs/feature-guides/administer-security-policies/policies/manage-policies/)",
		CreateContext: resourceApiKeyCreate,
		ReadContext:   resourceApiKeyRead,
		UpdateContext: resourceApiKeyUpdate,
		DeleteContext: resourceApiKeyDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the apikey",
			},
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the apikey in Banyan",
			},
			"description": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Description of the apikey",
			},
			"secret": {
				Type:        schema.TypeString,
				Description: "API Secret key",
				Computed:    true,
				Sensitive:   true,
				Optional:    true,
			},
			"scope": {
				Type:        schema.TypeString,
				Description: "API Secret key",
				Optional:    true,
			},
		},
	}
}

func resourceApiKeyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[APIKEY|RES|CREATE] creating apikey %s : %s", d.Get("name"), d.Id())
	client := m.(*client.Holder)

	k, err := client.ApiKey.Create(apikey.Post{
		Name:        d.Get("name").(string),
		Description: d.Get("description").(string),
		Scope:       d.Get("scope").(string),
	})
	if err != nil {
		return diag.FromErr(errors.WithMessage(err, "couldn't create new apikey"))
	}
	log.Printf("[APIKEY|RES|CREATE] created apikey %s : %s", d.Get("name"), d.Id())
	d.SetId(k.ID)
	diagnostics = resourceApiKeyRead(ctx, d, m)
	return
}

func resourceApiKeyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[APIKEY|RES|UPDATE] updating apikey %s : %s", d.Get("name"), d.Id())
	diagnostics = resourceApiKeyCreate(ctx, d, m)
	log.Printf("[APIKEY|RES|UPDATE] updated apikey %s : %s", d.Get("name"), d.Id())
	return
}

func resourceApiKeyRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[APIKEY|RES|READ] reading apikey %s : %s", d.Get("name"), d.Id())
	client := m.(*client.Holder)
	k, err := client.ApiKey.Get(d.Get("name").(string))
	emptykey := apikey.Data{}
	if k == emptykey {
		return handleNotFoundError(d, fmt.Sprintf("apikey %q", d.Id()))
	}
	err = d.Set("name", k.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("description", k.Description)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("secret", k.Secret)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("scope", k.Scope)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(d.Id())
	log.Printf("[APIKEY|RES|READ] read apikey %s : %s", d.Get("name"), d.Id())
	return
}

func resourceApiKeyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("[APIKEY|RES|DELETE] deleting apikey")

	client := m.(*client.Holder)
	err := client.ApiKey.Delete(d.Get("name").(string))
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	log.Println("[APIKEY|RES|DELETE] deleted apikey")
	d.SetId("")
	return
}
