package service_test

import (
	"testing"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/stretchr/testify/assert"
)

func Test_GetNonexistentService(t *testing.T) {
	testhost := client.GetBanyanHostUrl()
	apiKey := client.GetApiKey()
	myClient, err := client.NewClientHolder(testhost, apiKey)
	assert.NoError(t, err, "Expected to not get an error here")
	svc, err := myClient.Service.Get("hah")
	assert.NoError(t, err, "expected no error here")
	assert.Equal(t, service.GetServiceSpec{}, svc, "expected to get service x")
}

func Test_GetExistingService(t *testing.T) {
	testhost := client.GetBanyanHostUrl()
	apiKey := client.GetApiKey()
	myClient, err := client.NewClientHolder(testhost, apiKey)
	assert.NoError(t, err, "Expected to not get an error here")
	svc, err := myClient.Service.Get("testservice.us-west.bnn")
	assert.NoError(t, err, "expected no error here")
	assert.NotEqual(t, service.GetServiceSpec{}, svc, "expected to get service x")
}

func Test_CreateService(t *testing.T) {
	somestring := "test"
	testhost := client.GetBanyanHostUrl()
	apiKey := client.GetApiKey()
	myClient, err := client.NewClientHolder(testhost, apiKey)
	assert.NoError(t, err, "Expected to not get an error here")
	svc, err := myClient.Service.Create(service.CreateService{
		APIVersion: "rbac.banyanops.com/v1",
		Kind:       "BanyanService",
		Metadata: service.Metadata{
			ClusterName: "dev05-banyan",
			Description: "terraform test",
			Name:        "terraformtest",
			Tags: service.Tags{
				DescriptionLink: &somestring,
				Domain:          &somestring,
				Icon:            &somestring,
				Port:            &somestring,
				Protocol:        &somestring,
				ServiceAppType:  &somestring,
				Template:        &somestring,
				UserFacing:      &somestring,
			},
		},
		Spec: service.Spec{
			Attributes: service.Attributes{
				FrontendAddresses: []service.FrontendAddress{
					{
						CIDR: "0.0.0.0/32",
						Port: "1234",
					},
				},
				HostTagSelector: []map[string]string{
					{
						"ComBanyanopsHosttagSiteName": "TEST",
					},
				},
				TLSSNI: []string{"tf.tls.sni"},
			},
			Backend: service.Backend{
				// AllowPatterns: ,
				// DNSOverrides: ,
				HTTPConnect: false,
				Target: service.Target{
					ClientCertificate: false,
					Name:              "backend.domain",
					Port:              "9999",
					TLS:               false,
					TLSInsecure:       false,
				},
				// Whitelist: ,
			},
			CertSettings: service.CertSettings{
				CustomTLSCert: service.CustomTLSCert{},
				DNSNames:      []string{"https://service.domain.name"},
				Letsencrypt:   false,
			},
			// ClientCIDRs: ,
			HTTPSettings: service.HTTPSettings{
				Enabled:       true,
				ExemptedPaths: service.ExemptedPaths{},
				// Headers: ,
				HTTPHealthCheck: service.HTTPHealthCheck{},
				OIDCSettings: service.OIDCSettings{
					APIPath:              "",
					Enabled:              true,
					PostAuthRedirectPath: "",
					ServiceDomainName:    "https://service.domain.name",
				},
			},
		},
		Type: "origin",
	})
	assert.NoError(t, err, "expect no error when creating a service")
	assert.NotEqual(t, service.GetServiceSpec{}, svc, "expected to get service x")
}

func Test_CreateService2(t *testing.T) {
	somestring := "test"
	testhost := client.GetBanyanHostUrl()
	apiKey := client.GetApiKey()
	myClient, err := client.NewClientHolder(testhost, apiKey)
	assert.NoError(t, err, "Expected to not get an error here")
	svc, err := myClient.Service.Create(service.CreateService{
		APIVersion: "rbac.banyanops.com/v1",
		Kind:       "BanyanService",
		Metadata: service.Metadata{
			ClusterName: "dev05-banyan",
			Description: "terraform test",
			Name:        "terraformtest",
			Tags: service.Tags{
				DescriptionLink: &somestring,
				Domain:          &somestring,
				Icon:            &somestring,
				Port:            &somestring,
				Protocol:        &somestring,
				ServiceAppType:  &somestring,
				Template:        &somestring,
				UserFacing:      &somestring,
			},
		},
		Spec: service.Spec{
			Attributes: service.Attributes{
				FrontendAddresses: []service.FrontendAddress{
					{
						CIDR: "0.0.0.0/32",
						Port: "5555",
					},
				},
				HostTagSelector: []map[string]string{
					{
						"ComBanyanopsHosttagSiteName": "TEST",
					},
				},
				TLSSNI: []string{"tf.tls.sni"},
			},
			Backend: service.Backend{
				// AllowPatterns: ,
				// DNSOverrides: ,
				HTTPConnect: false,
				Target: service.Target{
					ClientCertificate: false,
					Name:              "backend.domain",
					Port:              "5555",
					TLS:               false,
					TLSInsecure:       false,
				},
				// Whitelist: ,
			},
			CertSettings: service.CertSettings{
				CustomTLSCert: service.CustomTLSCert{},
				DNSNames:      []string{"https://service.domain.name"},
				Letsencrypt:   false,
			},
			// ClientCIDRs: ,
			HTTPSettings: service.HTTPSettings{
				Enabled:       true,
				ExemptedPaths: service.ExemptedPaths{},
				// Headers: ,
				HTTPHealthCheck: service.HTTPHealthCheck{},
				OIDCSettings: service.OIDCSettings{
					APIPath:              "",
					Enabled:              true,
					PostAuthRedirectPath: "",
					ServiceDomainName:    "https://service.domain.name",
				},
			},
		},
		Type: "origin",
	})
	assert.NoError(t, err, "expect no error when creating a service")
	assert.NotEqual(t, service.GetServiceSpec{}, svc, "expected to get service x")
}

func Test_delete(t *testing.T) {
	testhost := client.GetBanyanHostUrl()
	apiKey := client.GetApiKey()
	myClient, err := client.NewClientHolder(testhost, apiKey)
	assert.NoError(t, err, "Expected to not get an error here")
	err = myClient.Service.Delete("terraformtest.dev05-banyan.bnn")
	assert.NoError(t, err)
}
