package service_test

import (
	"log"
	"os"
	"testing"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
)

func Test_GetNonexistentService(t *testing.T) {
	err := godotenv.Load("../../.env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	testhost := os.Getenv("BANYAN_HOST")
	testRefreshToken := os.Getenv("BANYAN_REFRESH_TOKEN")
	client, err := client.NewClientHolder(testhost, testRefreshToken)
	assert.NoError(t, err, "Expected to not get an error here")
	svc, ok, err := client.Service.Get("hah")
	assert.NoError(t, err, "expected no error here")
	assert.False(t, ok, "expected to get a value here")
	assert.Equal(t, service.GetServiceSpec{}, svc, "expected to get service x")
}

func Test_GetExistingService(t *testing.T) {
	err := godotenv.Load("../../.env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	testhost := os.Getenv("BANYAN_HOST")
	testRefreshToken := os.Getenv("BANYAN_REFRESH_TOKEN")
	client, err := client.NewClientHolder(testhost, testRefreshToken)
	assert.NoError(t, err, "Expected to not get an error here")
	svc, ok, err := client.Service.Get("a.dev05-banyan.bnn")
	assert.NoError(t, err, "expected no error here")
	assert.True(t, ok, "expected to get a value here")
	assert.NotEqual(t, service.GetServiceSpec{}, svc, "expected to get service x")
}

func Test_CreateService(t *testing.T) {
	err := godotenv.Load("../../.env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	testhost := os.Getenv("BANYAN_HOST")
	testRefreshToken := os.Getenv("BANYAN_REFRESH_TOKEN")
	client, err := client.NewClientHolder(testhost, testRefreshToken)
	assert.NoError(t, err, "Expected to not get an error here")
	svc, err := client.Service.Create(service.CreateService{
		APIVersion: "rbac.banyanops.com/v1",
		Kind:       "BanyanService",
		Metadata: service.Metadata{
			Cluster:     "dev05-banyan",
			Description: "terraform test",
			Name:        "terraformtest",
			Tags: service.Tags{
				DescriptionLink: "http://hello.com",
				Domain:          "tf.example.bnntest.com",
				Icon:            "",
				Port:            "443",
				Protocol:        "https",
				ServiceAppType:  "WEB",
				Template:        "WEB_USER", // should prefix with TF
				UserFacing:      "true",
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
				HostTagSelector: []service.HostTag{
					{
						ComBanyanopsHosttagSiteName: "TEST",
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
				LetsEncrypt:   false,
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
	err := godotenv.Load("../../.env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	testhost := os.Getenv("BANYAN_HOST")
	testRefreshToken := os.Getenv("BANYAN_REFRESH_TOKEN")
	client, err := client.NewClientHolder(testhost, testRefreshToken)
	assert.NoError(t, err, "Expected to not get an error here")
	svc, err := client.Service.Create(service.CreateService{
		APIVersion: "rbac.banyanops.com/v1",
		Kind:       "BanyanService",
		Metadata: service.Metadata{
			Cluster:     "dev05-banyan",
			Description: "terraform test",
			Name:        "terraformtest",
			Tags: service.Tags{
				DescriptionLink: "http://hello.com",
				Domain:          "tf.example.bnntest.com",
				Icon:            "",
				Port:            "443",
				Protocol:        "https",
				ServiceAppType:  "WEB",
				Template:        "WEB_USER", // should prefix with TF
				UserFacing:      "true",
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
				HostTagSelector: []service.HostTag{
					{
						ComBanyanopsHosttagSiteName: "TEST",
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
				LetsEncrypt:   false,
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
	err := godotenv.Load("../../.env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	testhost := os.Getenv("BANYAN_HOST")
	testRefreshToken := os.Getenv("BANYAN_REFRESH_TOKEN")
	client, err := client.NewClientHolder(testhost, testRefreshToken)
	assert.NoError(t, err, "Expected to not get an error here")
	err = client.Service.Delete("terraformtest.dev05-banyan.bnn")
	assert.NoError(t, err)
}
