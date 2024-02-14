package restclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is the struct used interact with the Banyan REST API.
type Client struct {
	accessToken string
	hostUrl     string
	httpClient  *http.Client
}

const defaultHostUrl = "https://net.banyanops.com"

// New creates a new client that will let the user interact with the REST API server.
func New(hostUrl string, apiKey string) (client *Client, err error) {
	clientHostUrl := defaultHostUrl
	if hostUrl != "" {
		clientHostUrl = hostUrl
	}

	if !strings.HasSuffix(hostUrl, "/") {
		clientHostUrl = hostUrl + "/"
	}

	client = &Client{
		accessToken: apiKey,
		hostUrl:     clientHostUrl,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
	}

	return
}

// DoPut posts a message to host url, with the method path and body listed
func (c *Client) DoPut(path string, body io.Reader) (response *http.Response, err error) {
	req, err := c.NewRequest(http.MethodPut, path, body)
	if err != nil {
		return
	}
	response, err = c.Do(req)
	return
}

// DoPost posts a message to host url, with the method path and body listed
func (c *Client) DoPost(path string, body io.Reader) (response *http.Response, err error) {
	req, err := c.NewRequest(http.MethodPost, path, body)
	if err != nil {
		return
	}
	response, err = c.Do(req)
	return
}

// DoGet sends and does the get request
func (c *Client) DoGet(path string) (response *http.Response, err error) {
	request, err := c.Get(path)
	if err != nil {
		return
	}
	response, err = c.Do(request)
	return
}

// DoDelete sends the delete request
func (c *Client) DoDelete(path string) (response *http.Response, err error) {
	request, err := c.delete(path)
	if err != nil {
		return
	}
	response, err = c.Do(request)
	return
}

func (c *Client) delete(path string) (request *http.Request, err error) {
	return c.NewRequest(http.MethodDelete, path, nil)
}

// Get creates a new Get request, saving the user from needing to pass in a nil value
func (c *Client) Get(path string) (request *http.Request, err error) {
	return c.NewRequest("GET", path, nil)
}

// Do execute the request and returns the response
func (c *Client) Do(request *http.Request) (response *http.Response, err error) {
	return c.httpClient.Do(request)
}

// NewRequest creates a new request with the accessToken added as a header
func (c *Client) NewRequest(method string, path string, body io.Reader) (request *http.Request, err error) {
	return c.newRequest(method, c.hostUrl+path, body)
}

func (c *Client) newRequest(method string, url string, body io.Reader) (request *http.Request, err error) {
	request, err = http.NewRequest(method, url, body)
	if err != nil {
		return
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.accessToken))
	return
}

// This will be depreciated out fo the provider which will only use API keys

type ErrorResponse struct {
	Message string `json:"error_description"`
}

func (c *Client) Read(api string, component string, id string, path string) (resp []byte, err error) {
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
	if err != nil {
		err = errors.Join(fmt.Errorf("request to %s %s failed", response.Request.Method, response.Request.URL.String()), err)
		return
	}
	return HandleResponse(response)
}

func (c *Client) ReadQuery(component string, query url.Values, path string) (r []byte, err error) {
	myUrl, err := url.Parse(path)
	if err != nil {
		return
	}
	myUrl.RawQuery = query.Encode()
	response, err := c.DoGet(myUrl.String())
	if err != nil {
		err = errors.Join(fmt.Errorf("request to %s %s failed", response.Request.Method, response.Request.URL.String()), err)
		return
	}
	return HandleResponse(response)
}

func (c *Client) Create(api string, component string, body []byte, path string) (r []byte, err error) {
	if path == "" {
		path = fmt.Sprintf("%s/%s", api, component)
	}
	request, err := c.NewRequest(http.MethodPost, path, bytes.NewBuffer(body))
	if err != nil {
		err = errors.Join(fmt.Errorf("request formation failed for %s %s", request.Method, request.URL.String()), err)
		return
	}
	response, err := c.Do(request)
	if err != nil {
		err = errors.Join(fmt.Errorf("request to %s %s failed", request.Method, request.URL.String()), err)
		return
	}
	return HandleResponse(response)
}

func (c *Client) Update(api string, component string, id string, body []byte, path string) (r []byte, err error) {
	if path == "" {
		path = fmt.Sprintf("%s/%s/%s", api, component, id)
	}
	request, err := c.NewRequest(http.MethodPut, path, bytes.NewBuffer(body))
	if err != nil {
		err = errors.Join(fmt.Errorf("request formation failed for %s %s", request.Method, request.URL.String()), err)
		return
	}
	response, err := c.Do(request)
	if err != nil {
		err = errors.Join(fmt.Errorf("request to %s %s failed", request.Method, request.URL.String()), err)
		return
	}

	return HandleResponse(response)
}

func (c *Client) Delete(api string, component string, id string, path string) (err error) {
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
	if err != nil {
		err = errors.Join(fmt.Errorf("request to %s %s failed", response.Request.Method, response.Request.URL.String()), err)
		return
	}

	_, err = HandleResponse(response)
	return
}

func (c *Client) DeleteQuery(component string, id string, query url.Values, path string) (err error) {
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
	if err != nil {
		err = errors.Join(fmt.Errorf("request to %s %s failed", response.Request.Method, response.Request.URL.String()), err)
		return
	}
	_, err = HandleResponse(response)
	return
}

func HandleResponse(response *http.Response) (responseData []byte, err error) {
	defer response.Body.Close()
	requestStr := fmt.Sprintf("%s %s", response.Request.Method, response.Request.URL.String())
	responseData, err = io.ReadAll(response.Body)
	if err != nil {
		return
	}
	if response.StatusCode == 400 {
		err = fmt.Errorf("%d bad request: %s \n Response: \n %s", response.StatusCode, requestStr, responseData)
		return
	}
	if response.StatusCode == 404 {
		err = fmt.Errorf("404 not found: %s", requestStr)
		return
	}
	if response.StatusCode != 200 {
		var errResp ErrorResponse
		if err != nil {
			return
		}
		uerr := json.Unmarshal(responseData, &errResp)
		if uerr == nil {
			err = fmt.Errorf("recieved error code %d: %s \n response: \n %s", response.StatusCode, requestStr, responseData)
		}
		return
	}
	return
}
