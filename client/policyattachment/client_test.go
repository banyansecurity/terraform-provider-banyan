package policyattachment_test

import (
	"testing"

	"github.com/banyansecurity/terraform-banyan-provider/client/policyattachment"
	"github.com/banyansecurity/terraform-banyan-provider/client/testutil"
	"github.com/stretchr/testify/assert"
)

func Test_GetNonexistentRole(t *testing.T) {
	emptyAttachment := policyattachment.GetBody{}
	client, err := testutil.GetClientHolderForTest()
	assert.NoError(t, err, "Expected to not get an error here")
	role, ok, err := client.PolicyAttachment.Get("heh", "hi", "service")
	assert.NoError(t, err, "expected no error here")
	assert.False(t, ok, "expected to get a value here")

	assert.Equal(t, emptyAttachment, role, "expected to get empty attachment")
}

func Test_GetExistingRole(t *testing.T) {
	client, err := testutil.GetClientHolderForTest()
	assert.NoError(t, err, "Expected to not get an error here")
	emptyAttachment := policyattachment.GetBody{}

	attachment, ok, err := client.PolicyAttachment.Get("9e77de1a-c886-4eb0-9548-15fa4085d497", "demo-day-lets-encrypt-2.dev05-banyan.bnn", "service")
	assert.NoError(t, err, "expected no error here")
	assert.True(t, ok, "expected to get a value here")
	assert.NotEqual(t, emptyAttachment, attachment, "expected to a full policy attachment x")
}

func Test_CreateGetUpdateGetThenDeleteAttachment(t *testing.T) {
	everyonePolicyID := "9e77de1a-c886-4eb0-9548-15fa4085d497"
	serviceToAttachToID := "realtftest.dev05-banyan.bnn"
	attachedToType := "service"
	client, err := testutil.GetClientHolderForTest()
	assert.NoError(t, err, "Expected to not get an error here")
	createAttachment := policyattachment.CreateBody{
		AttachedToID:   serviceToAttachToID,
		AttachedToType: attachedToType,
		IsEnabled:      true,
		Enabled:        "TRUE",
	}
	createdAttachment, err := client.PolicyAttachment.Create(everyonePolicyID, createAttachment)
	assert.NoError(t, err)
	retrievedAttachment, ok, err := client.PolicyAttachment.Get(everyonePolicyID, serviceToAttachToID, attachedToType)
	assert.NoError(t, err)
	assert.True(t, ok)
	// handle slight bug here
	createdAttachment.PolicyName = "Everyone"
	createdAttachment.AttachedToName = "realtftest"
	assert.Equal(t, createdAttachment, retrievedAttachment)
	createAttachment.IsEnabled = false
	createAttachment.Enabled = "FALSE"
	updatedAttachment, err := client.PolicyAttachment.Update(everyonePolicyID, createAttachment)
	assert.NoError(t, err)
	assert.NotEqual(t, updatedAttachment, createdAttachment)
	retrievedAttachment, ok, err = client.PolicyAttachment.Get(everyonePolicyID, serviceToAttachToID, attachedToType)
	assert.NoError(t, err)
	assert.True(t, ok)
	updatedAttachment.PolicyName = "Everyone"
	updatedAttachment.AttachedToName = "realtftest"
	assert.Equal(t, updatedAttachment, retrievedAttachment)

	client.PolicyAttachment.Delete(everyonePolicyID, policyattachment.DetachBody{
		AttachedToID: serviceToAttachToID,
		AttachedToType: attachedToType,
	})
	retrievedAttachment, ok, err = client.PolicyAttachment.Get(everyonePolicyID, serviceToAttachToID, attachedToType)
	assert.NoError(t, err)
	assert.False(t, ok)
}
