package shield

import (
	"encoding/json"
	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
	"log"
)

const apiVersion = "api/v2"
const component = "shield_config"

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

type Client struct {
	restClient *restclient.RestClient
}

func NewClient(restClient *restclient.RestClient) Clienter {
	c := Client{
		restClient: restClient,
	}
	return &c
}

type Clienter interface {
	GetAll() (shields []string, err error)
}

func (c *Client) GetAll() (shields []string, err error) {
	log.Printf("getting shields")
	resp, err := c.restClient.Read(apiVersion, component, "", "")
	var j ResponseBody
	err = json.Unmarshal(resp, &j)
	if err != nil {
		return
	}
	sInfo := j.Data.Configs
	for _, info := range sInfo {
		shields = append(shields, info.ShieldName)
	}
	return
}
