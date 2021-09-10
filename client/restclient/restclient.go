package restclient

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/pkg/errors"
)

// Client is the struct that you use to interact with the banyan restapi.
type RestClient struct {
	accessToken string
	hostUrl     string
	httpClient  *http.Client
}

const defaultHostUrl = "http://net.banyanops.com"

// New creates a new client that will let the user interact with the restapi server.
// As part of this it exchanges the given refreshtoken for an acesstoken.
func New(hostUrl string, refreshToken string) (client *RestClient, err error) {
	if refreshToken == "" {
		err = errors.New("need a refresh token")
		return
	}
	clientHostUrl := defaultHostUrl
	if hostUrl != "" {
		clientHostUrl = hostUrl
	}

	client = &RestClient{
		accessToken: "",
		hostUrl:     clientHostUrl,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
	}

	accessToken, err := client.exhangeRefreshTokenForAccessToken(clientHostUrl, refreshToken)
	if err != nil {
		errors.Wrapf(err, "Issue exchanging refreshToken for accessToken")
		return
	}

	client = &RestClient{
		accessToken: accessToken,
		hostUrl:     clientHostUrl,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
	}

	return
}


// DoPut posts a message to host url, with the method path and body listsed
func (this *RestClient) DoPut(path string, body io.Reader) (response *http.Response, err error) {
	req, err := this.NewRequest(http.MethodPut, path, body)
	if err != nil {
		return
	}
	response, err = this.Do(req)
	return
}

// DoPost posts a message to host url, with the method path and body listsed
func (this *RestClient) DoPost(path string, body io.Reader) (response *http.Response, err error) {
	req, err := this.NewRequest(http.MethodPost, path, body)
	if err != nil {
		return
	}
	response, err = this.Do(req)
	return
}

// DoGet sends and does the get request
func (this *RestClient) DoGet(path string) (response *http.Response, err error) {
	request, err := this.Get(path)
	if err != nil {
		return
	}
	response, err = this.Do(request)
	return
}

func (this *RestClient) delete(path string) (request *http.Request, err error) {
	return this.NewRequest(http.MethodDelete, path, nil)
}

func (this *RestClient) DoDelete(path string) (response *http.Response, err error) {
	request, err := this.delete(path)
	if err != nil {
		return
	}
	response, err = this.Do(request)
	return
}

// get creates a new Get request, saving the user of needing to pass in a nil value
func (this *RestClient) Get(path string) (request *http.Request, err error) {
	return this.NewRequest("GET", path, nil)
}

func (this *RestClient) Do(request *http.Request) (response *http.Response, err error) {
	return this.httpClient.Do(request)
}

// get creates a new Get request, saving the user of needing to pass in a nil value
func (this *RestClient) get(url string) (request *http.Request, err error) {
	return this.newRequest("GET", url, nil)
}

func (this *RestClient) NewRequest(method string, path string, body io.Reader) (request *http.Request, err error) {
	return this.newRequest(method, this.hostUrl+path, body)
}

// newRequest creates a new request with the accessToken added as a header
func (this *RestClient) newRequest(method string, url string, body io.Reader) (request *http.Request, err error) {
	request, err = http.NewRequest(method, url, body)
	if err != nil {
		return
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", this.accessToken))
	return
}

func (this *RestClient) exhangeRefreshTokenForAccessToken(clientHostUrl string, refreshToken string) (accessToken string, err error) {
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
		err = errors.WithMessage(err, "unable to unmarshal the accessToken, "+string(body))
		return
	}
	accessToken = accessTokenStruct.Message

	return
}
