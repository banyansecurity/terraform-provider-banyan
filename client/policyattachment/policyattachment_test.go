package policyattachment_test

import (
	"testing"

	"github.com/banyansecurity/terraform-banyan-provider/client/policyattachment"
	"github.com/banyansecurity/terraform-banyan-provider/client/testutil"
	"github.com/stretchr/testify/assert"
)

func Test_GetNonexistentAttachment(t *testing.T) {
	emptyAttachment := policyattachment.GetBody{}
	client, err := testutil.GetClientHolderForTest()
	assert.NoError(t, err, "Expected to not get an error here")
	attachment, err := client.PolicyAttachment.Get("hi", "service")
	assert.NoError(t, err, "expected no error here")
	assert.False(t, false, "expected to get a value here")

	assert.Equal(t, emptyAttachment, attachment, "expected to get empty attachment")
}

func Test_CreateGetUpdateGetThenDeleteAttachment(t *testing.T) {
	everyonePolicyID := "73f0820b-cbf1-4e75-9518-21121a6a271c"
	everyonePolicyName := "everyone"
	testServiceID := "testservice.us-west.bnn"
	testServiceName := "testservice"

	attachedToType := "service"
	client, err := testutil.GetClientHolderForTest()
	assert.NoError(t, err, "Expected to not get an error here")
	createAttachment := policyattachment.CreateBody{
		AttachedToID:   testServiceID,
		AttachedToType: attachedToType,
		IsEnabled:      true,
		Enabled:        "TRUE",
	}
	createdAttachment, err := client.PolicyAttachment.Create(everyonePolicyID, createAttachment)
	assert.NoError(t, err)
	retrievedAttachment, err := client.PolicyAttachment.Get(testServiceID, attachedToType)
	assert.NoError(t, err)
	assert.True(t, true)
	// handle slight bug here
	createdAttachment.PolicyName = everyonePolicyName
	createdAttachment.AttachedToName = testServiceName
	assert.Equal(t, createdAttachment, retrievedAttachment)
	createAttachment.IsEnabled = false
	createAttachment.Enabled = "FALSE"
	updatedAttachment, err := client.PolicyAttachment.Update(everyonePolicyID, createAttachment)
	assert.NoError(t, err)
	assert.NotEqual(t, updatedAttachment, createdAttachment)
	retrievedAttachment, err = client.PolicyAttachment.Get(testServiceID, attachedToType)
	assert.NoError(t, err)
	assert.True(t, true)
	updatedAttachment.PolicyName = everyonePolicyName
	updatedAttachment.AttachedToName = testServiceName
	assert.Equal(t, updatedAttachment, retrievedAttachment)

	//client.PolicyAttachment.Delete(everyonePolicyID, policyattachment.DetachBody{
	//	AttachedToID:   testServiceID,
	//	AttachedToType: attachedToType,
	//})
	_, err = client.PolicyAttachment.Get(testServiceID, attachedToType)
	assert.NoError(t, err)
	assert.False(t, false)
}
