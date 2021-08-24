package client

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/pkg/errors"
)

const defaultHostUrl = "http://net.banyanops.com/"

// type BnnClient interface {
// 	OidcSettingsClienter
// 	OrgIdpConfigClienter
// }

// Client is the struct that you use to interact with the banyan restapi.
type Client struct {
	accessToken string
	hostUrl     string
	httpClient  *http.Client
}

// New creates a new client that will let the user interact with the restapi server.
// As part of this it exchanges the given refreshtoken for an acesstoken.
func New(hostUrl string, refreshToken string) (client *Client, err error) {
	if refreshToken == "" {
		err = errors.New("need a refresh token")
		return
	}
	clientHostUrl := defaultHostUrl
	if hostUrl != "" {
		clientHostUrl = hostUrl
	}

	client = &Client{
		accessToken: "",
		hostUrl:     clientHostUrl,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
	}

	accessToken, err := client.exhangeRefreshTokenForAccessToken(clientHostUrl, refreshToken)
	if err != nil {
		errors.Wrapf(err, "Issue exchanging refreshToken for accessToken")
		return
	}

	client = &Client{
		accessToken: accessToken,
		hostUrl:     clientHostUrl,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
	}

	return
}

// get creates a new Get request, saving the user of needing to pass in a nil value
func (this *Client) get(url string) (request *http.Request, err error) {
	return this.newRequest("GET", url, nil)
}

// newRequest creates a new request with the accessToken added as a header
func (this *Client) newRequest(method string, url string, body io.Reader) (request *http.Request, err error) {
	request, err = http.NewRequest(method, url, body)
	if err != nil {
		return
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", this.accessToken))
	return
}

func (this *Client) exhangeRefreshTokenForAccessToken(clientHostUrl string, refreshToken string) (accessToken string, err error) {
	req, err := http.NewRequest("POST", clientHostUrl+"api/v1/refresh_token", nil)
	req.Header.Add("Authorization", "Bearer "+refreshToken)
	resp, err := this.httpClient.Do(req)
	if err != nil {
		err = errors.WithMessage(err, "Unable to make actual request for accesstoken")
		return
	}
	if resp.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("invalid status code %+v", resp))
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		err = errors.WithMessage(err, "Unable to read accessToken body")
		return
	}
	return getAccessTokenFromJSON(body)
}

func getAccessTokenFromJSON(body []byte) (accessToken string, err error) {
	type AccessToken struct {
		Message string
	}

	var accessTokenStruct AccessToken
	err = json.Unmarshal(body, &accessTokenStruct)
	if err != nil {
		err = errors.WithMessage(err, "unable to unmarshall the accessToken, "+string(body))
		return
	}
	accessToken = accessTokenStruct.Message

	return
}
