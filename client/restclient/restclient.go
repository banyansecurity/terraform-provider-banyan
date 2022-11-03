package restclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// RestClient is the struct used interact with the Banyan REST API.
type RestClient struct {
	accessToken string
	hostUrl     string
	httpClient  *http.Client
}

const defaultHostUrl = "https://net.banyanops.com"

// New creates a new client that will let the user interact with the REST API server.
// As part of this it exchanges the given refreshtoken or api key
func New(hostUrl string, refreshToken string, apiToken string) (client *RestClient, err error) {
	clientHostUrl := defaultHostUrl
	if hostUrl != "" {
		clientHostUrl = hostUrl
	}

	if !strings.HasSuffix(hostUrl, "/") {
		clientHostUrl = hostUrl + "/"
	}

	var accessToken string
	if refreshToken != "" {
		client = &RestClient{
			accessToken: "",
			hostUrl:     clientHostUrl,
			httpClient:  &http.Client{Timeout: 10 * time.Second},
		}

		accessToken, err = client.exhangeRefreshTokenForAccessToken(clientHostUrl, refreshToken)
		if err != nil {
			errors.Wrapf(err, "Issue exchanging refreshToken for accessToken")
			return
		}
	}

	if apiToken != "" {
		accessToken = apiToken
	}

	client = &RestClient{
		accessToken: accessToken,
		hostUrl:     clientHostUrl,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
	}

	return
}

// DoPut posts a message to host url, with the method path and body listed
func (c *RestClient) DoPut(path string, body io.Reader) (response *http.Response, err error) {
	req, err := c.NewRequest(http.MethodPut, path, body)
	if err != nil {
		return
	}
	response, err = c.Do(req)
	return
}

// DoPost posts a message to host url, with the method path and body listed
func (c *RestClient) DoPost(path string, body io.Reader) (response *http.Response, err error) {
	req, err := c.NewRequest(http.MethodPost, path, body)
	if err != nil {
		return
	}
	response, err = c.Do(req)
	return
}

// DoGet sends and does the get request
func (c *RestClient) DoGet(path string) (response *http.Response, err error) {
	request, err := c.Get(path)
	if err != nil {
		return
	}
	response, err = c.Do(request)
	return
}

// DoDelete sends the delete request
func (c *RestClient) DoDelete(path string) (response *http.Response, err error) {
	request, err := c.delete(path)
	if err != nil {
		return
	}
	response, err = c.Do(request)
	return
}

func (c *RestClient) delete(path string) (request *http.Request, err error) {
	return c.NewRequest(http.MethodDelete, path, nil)
}

// Get creates a new Get request, saving the user from needing to pass in a nil value
func (c *RestClient) Get(path string) (request *http.Request, err error) {
	return c.NewRequest("GET", path, nil)
}

func (c *RestClient) get(url string) (request *http.Request, err error) {
	return c.newRequest("GET", url, nil)
}

// Do executes the request and returns the response
func (c *RestClient) Do(request *http.Request) (response *http.Response, err error) {
	return c.httpClient.Do(request)
}

// NewRequest creates a new request with the accessToken added as a header
func (c *RestClient) NewRequest(method string, path string, body io.Reader) (request *http.Request, err error) {
	return c.newRequest(method, c.hostUrl+path, body)
}

func (c *RestClient) newRequest(method string, url string, body io.Reader) (request *http.Request, err error) {
	request, err = http.NewRequest(method, url, body)
	if err != nil {
		return
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.accessToken))
	return
}

func (c *RestClient) exhangeRefreshTokenForAccessToken(clientHostUrl string, refreshToken string) (accessToken string, err error) {
	req, err := http.NewRequest("POST", clientHostUrl+"api/v1/refresh_token", nil)
	req.Header.Add("Authorization", "Bearer "+refreshToken)
	resp, err := c.httpClient.Do(req)
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

type ErrorResponse struct {
	Message string `json:"error_description"`
}

func (c *RestClient) Read(api string, component string, id string, path string) (resp []byte, err error) {
	if id == "" {
		err = fmt.Errorf("need an id to get %s", component)
		return
	}
	if path == "" {
		path = fmt.Sprintf("%s/%s/%s", api, component, id)
	}
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	response, err := c.DoGet(myUrl.String())
	return HandleResponse(response, component)
}

func (c *RestClient) ReadQuery(component string, query url.Values, path string) (r []byte, err error) {
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	myUrl.RawQuery = query.Encode()
	response, err := c.DoGet(myUrl.String())
	if err != nil {
		return
	}
	return HandleResponse(response, component)
}

func (c *RestClient) Create(api string, component string, body []byte, path string) (r []byte, err error) {
	if path == "" {
		path = fmt.Sprintf("%s/%s", api, component)
	}
	request, err := c.NewRequest(http.MethodPost, path, bytes.NewBuffer(body))
	if err != nil {
		return
	}
	response, err := c.Do(request)
	if err != nil {
		return
	}
	return HandleResponse(response, component)
}

func (c *RestClient) Update(api string, component string, id string, body []byte, path string) (r []byte, err error) {
	if path == "" {
		path = fmt.Sprintf("%s/%s/%s", api, component, id)
	}
	request, err := c.NewRequest(http.MethodPut, path, bytes.NewBuffer(body))
	if err != nil {
		return
	}
	response, err := c.Do(request)
	return HandleResponse(response, component)
}

func (c *RestClient) Delete(api string, component string, id string, path string) (err error) {
	if id == "" {
		err = fmt.Errorf("need an id to delete %s", component)
		return
	}
	if path == "" {
		path = fmt.Sprintf("%s/%s/%s", api, component, id)
	}
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	response, err := c.DoDelete(myUrl.String())
	_, err = HandleResponse(response, component)
	return
}

func (c *RestClient) DeleteQuery(component string, id string, query url.Values, path string) (err error) {
	if id == "" {
		err = fmt.Errorf("need an id to delete %s", component)
		return
	}
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	myUrl.RawQuery = query.Encode()
	response, err := c.DoDelete(myUrl.String())
	_, err = HandleResponse(response, component)
	return
}

func HandleResponse(response *http.Response, component string) (responseData []byte, err error) {
	defer response.Body.Close()
	responseData, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	if response.StatusCode == 404 || response.StatusCode == 400 {
		err = fmt.Errorf("%s not found", component)
		return
	}
	if response.StatusCode != 200 {
		var errResp ErrorResponse
		if err != nil {
			return
		}
		uerr := json.Unmarshal(responseData, &errResp)
		if uerr == nil {
			err = fmt.Errorf("received error code %d with message: %s", response.StatusCode, errResp.Message)
		}
		return
	}
	return
}
