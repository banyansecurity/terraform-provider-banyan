package shield

import (
	"encoding/json"
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
	"log"
	"net/url"
)

type Shield struct {
	Clusters []Info
}

type ResponseBody struct {
	Data Data `json:"data"`
}

type Data struct {
	Configs []Info `json:"Configs"`
}

type Info struct {
	ShieldName string `json:"ShieldName"`
}

type shield struct {
	restClient *restclient.Client
}

func NewClient(restClient *restclient.Client) Client {
	c := shield{
		restClient: restClient,
	}
	return &c
}

type Client interface {
	GetAll() (shields []string, err error)
}

func (s *shield) GetAll() (shields []string, err error) {
	log.Printf("getting shields")
	path := fmt.Sprintf("api/v2/shield_config")
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	response, err := s.restClient.DoGet(myUrl.String())
	if err != nil {
		return
	}
	responseData, err := restclient.HandleResponse(response, "shield")
	if err != nil {
		return
	}
	var Json ResponseBody
	err = json.Unmarshal(responseData, &Json)
	if err != nil {
		return
	}
	sInfo := Json.Data.Configs
	for _, info := range sInfo {
		shields = append(shields, info.ShieldName)
	}
	return
}
