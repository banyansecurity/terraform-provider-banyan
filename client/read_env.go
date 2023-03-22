package client

import (
	"log"
	"net/url"
	"os"
)

func GetBanyanHostUrl() string {
	envUrl, err := url.Parse(os.Getenv("BANYAN_HOST"))
	if err != nil {
		log.Println(err)
		log.Fatal("Could not create the test client")
	}
	if envUrl.Scheme != "https" {
		envUrl.Scheme = "https"
	}
	return envUrl.String()
}

func GetApiKey() string {
	apiKey := os.Getenv("BANYAN_API_KEY")
	if apiKey == "" {
		log.Fatal("require BANYAN_API_KEY, Could not create the test client")
	}
	return apiKey
}
