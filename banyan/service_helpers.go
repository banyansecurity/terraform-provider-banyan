package banyan

import (
	"context"
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/policyattachment"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
)

func resourceServiceDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	svc, err := c.Service.Get(d.Id())
	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	err = c.Service.DetachPolicy(svc.ServiceID)
	if err != nil {
		return diag.FromErr(err)
	}
	err = c.Service.Delete(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
	}
	return
}

// common function to create a service
func resourceServiceCreate(svc service.CreateService, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	created, err := c.Service.Create(svc)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(created.ServiceID)
	err = attachPolicyToService(d, c)
	if err != nil {
		return diag.FromErr(err)
	}
	return
}

func attachPolicyToService(d *schema.ResourceData, c *client.Holder) (err error) {
	log.Printf("[INFO] Getting policy for attachment %s", d.Id())
	currentPolicy, err := c.Service.GetPolicyForService(d.Id())
	if currentPolicy.ID != "" {
		err = c.Policy.Detach(c.PolicyAttachment, currentPolicy.ID)
		if err != nil {
			return
		}
	}
	policyID := d.Get("policy").(string)
	if policyID == "" {
		return
	}
	pol, err := c.Policy.Get(policyID)
	if err != nil {
		return
	}
	if pol.ID == "" {
		return fmt.Errorf("policy with id %s not found", policyID)
	}
	body := policyattachment.CreateBody{
		AttachedToID:   d.Get("id").(string),
		AttachedToType: "service",
		IsEnabled:      true,
		Enabled:        "TRUE",
	}
	pa, err := c.PolicyAttachment.Create(policyID, body)
	if err != nil {
		return
	}
	log.Printf("[INFO] Created policy attachment %s : %s", pa.PolicyID, pa.AttachedToID)
	return
}

func resourceServiceUpdate(svc service.CreateService, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	_, err := c.Service.Get(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	_, err = c.Service.Update(d.Id(), svc)
	if err != nil {
		return diag.FromErr(err)
	}
	err = attachPolicyToService(d, c)
	if err != nil {
		return diag.FromErr(err)
	}
	return
}
