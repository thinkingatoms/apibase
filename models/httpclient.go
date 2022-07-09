package models

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/schema"
	"github.com/rs/zerolog/log"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type UnknownError struct {
	StatusCode int
	Message    string
	Request    *http.Request
}

func (self *UnknownError) Error() string {
	return fmt.Sprintf("%d: %s", self.StatusCode, self.Message)
}

type ClientError struct {
	StatusCode int
	Message    string
	Request    *http.Request
}

func (self *ClientError) Error() string {
	return fmt.Sprintf("%d: %s", self.StatusCode, self.Message)
}

type ServerError struct {
	StatusCode int
	Message    string
	Request    *http.Request
}

func (self *ServerError) Error() string {
	return fmt.Sprintf("%d: %s", self.StatusCode, self.Message)
}

type HTTPClient struct {
	rootURL string
	Client  *http.Client
}

func (self *HTTPClient) Do(req *http.Request, err error) (*http.Response, error) {
	if err != nil {
		return nil, err
	}
	resp, err := self.Client.Do(req)
	return self.CheckStatusCode(req, resp, err)
}

func (self *HTTPClient) getURL(path string) string {
	if strings.HasPrefix(path, "http") {
		return path
	} else if strings.HasPrefix(path, "/") {
		return self.rootURL + path[1:]
	}
	return self.rootURL + path
}

func (self *HTTPClient) CheckStatusCode(req *http.Request, resp *http.Response, err error) (*http.Response, error) {
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(resp.Body)

		body, _ := ioutil.ReadAll(resp.Body)
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return nil, &ClientError{
				StatusCode: resp.StatusCode,
				Message:    string(body),
				Request:    req,
			}
		} else if resp.StatusCode >= 500 {
			return nil, &ServerError{
				StatusCode: resp.StatusCode,
				Message:    string(body),
				Request:    req,
			}
		}
		return nil, &UnknownError{
			StatusCode: resp.StatusCode,
			Message:    string(body),
			Request:    req,
		}
	}
	return resp, nil
}

func (self *HTTPClient) GetPostJSONRequest(path string, data any) (*http.Request, error) {
	body, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	var req *http.Request
	req, err = http.NewRequest("POST", self.getURL(path), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	return req, err
}

func (self *HTTPClient) PostJSON(path string, data any) (*http.Response, error) {
	return self.Do(self.GetPostJSONRequest(path, data))
}

func (self *HTTPClient) GetPostValuesRequest(path string, form *url.Values) (*http.Request, error) {
	req, err := http.NewRequest("POST", self.getURL(path), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, err
}

func (self *HTTPClient) PostValues(path string, form *url.Values) (*http.Response, error) {
	return self.Do(self.GetPostValuesRequest(path, form))
}

var encoder = schema.NewEncoder()

func (self *HTTPClient) GetPostObjectRequest(path string, obj any) (*http.Request, error) {
	form := make(url.Values)
	err := encoder.Encode(obj, form)
	if err != nil {
		return nil, err
	}
	return self.GetPostValuesRequest(path, &form)
}

func (self *HTTPClient) PostObject(path string, obj any) (*http.Response, error) {
	return self.Do(self.GetPostObjectRequest(path, obj))
}

func (self *HTTPClient) GetGetRequest(path string, values url.Values) (*http.Request, error) {
	req, err := http.NewRequest("GET", self.getURL(path), nil)
	if err != nil {
		return nil, err
	}
	if values != nil {
		q := req.URL.Query()
		for k, v := range values {
			if len(v) > 0 {
				q.Set(k, v[0])
			}
		}
		req.URL.RawQuery = q.Encode()
	}
	return req, err
}

func (self *HTTPClient) Get(path string, values url.Values) (*http.Response, error) {
	return self.Do(self.GetGetRequest(path, values))
}

func (self *HTTPClient) ToJSON(resp *http.Response, err error) (map[string]any, error) {
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New("failed to read response body: " + err.Error())
	}
	var ret map[string]any
	err = json.Unmarshal(body, &ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (self *HTTPClient) ToBytes(resp *http.Response, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New("failed to read response body: " + err.Error())
	}
	return body, nil
}

func NewHTTPClient(rootURL string, timeout int, maxIdleConns int, maxPerHost int) *HTTPClient {
	if rootURL == "" {
		panic("root url is required")
	}
	if !strings.HasSuffix(rootURL, "/") {
		rootURL += "/"
	}
	return &HTTPClient{
		rootURL: rootURL,
		Client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        maxIdleConns,
				MaxConnsPerHost:     maxPerHost,
				MaxIdleConnsPerHost: maxPerHost,
			},
		},
	}
}

type APIClient struct {
	*HTTPClient
	credential   *ClientCredential
	accessURL    string
	refreshURL   string
	accessToken  string
	refreshToken string
	cred         string
}

func (self *APIClient) Do(req *http.Request, err error) (*http.Response, error) {
	if err != nil {
		return nil, err
	}
	if self.accessToken == "" {
		err := self.LoadToken()
		if err != nil {
			return nil, err
		}
	}
	//fmt.Println("access token:", req, self.accessToken)
	req.Header.Set("Authorization", self.accessToken)
	ret, err := self.HTTPClient.Do(req, nil)
	if err != nil {
		switch err.(type) {
		case *ClientError:
			err = self.RefreshToken()
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", self.accessToken)
			return self.HTTPClient.Do(req, nil)
		default:
			return nil, err
		}
	}
	return ret, err
}

func (self *APIClient) LoadToken() error {
	if self.cred == "" {
		dump, err := json.Marshal(self.credential)
		if err != nil {
			return err
		}
		self.cred = string(dump)
	}
	//fmt.Println("cred:", self.cred)
	req, err := http.NewRequest("POST", self.accessURL, strings.NewReader(self.cred))
	if err != nil {
		return err
	}
	ret, err := self.ToJSON(self.HTTPClient.Do(req, nil))
	if err != nil {
		return err
	}
	self.accessToken = "Bearer " + ret["accessToken"].(string)
	self.refreshToken = "Bearer " + ret["refreshToken"].(string)
	return nil
}

func (self *APIClient) RefreshToken() error {
	req, err := http.NewRequest("GET", self.refreshURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", self.refreshToken)
	var ret map[string]any
	ret, err = self.ToJSON(self.HTTPClient.Do(req, nil))
	if err != nil {
		switch err.(type) {
		case *ClientError:
			log.Error().Msgf("failed to refresh token: %s", err.Error())
			err = self.LoadToken()
			return err
		default:
			return err
		}
	}
	self.accessToken = "Bearer " + ret["accessToken"].(string)
	self.refreshToken = "Bearer " + ret["refreshToken"].(string)
	return nil
}

func (self *APIClient) PostJSON(path string, data any) (*http.Response, error) {
	return self.Do(self.GetPostJSONRequest(path, data))
}

func (self *APIClient) PostValues(path string, form *url.Values) (*http.Response, error) {
	return self.Do(self.GetPostValuesRequest(path, form))
}

func (self *APIClient) PostObject(path string, obj any) (*http.Response, error) {
	return self.Do(self.GetPostObjectRequest(path, obj))
}

func (self *APIClient) Get(path string, values url.Values) (*http.Response, error) {
	return self.Do(self.GetGetRequest(path, values))
}

func NewAPIClient(rootURL, accessURL, refreshURL, clientID, clientSecret string,
	timeout int, maxIdleConns int, maxPerHost int) *APIClient {
	return &APIClient{
		HTTPClient: NewHTTPClient(rootURL, timeout, maxIdleConns, maxPerHost),
		accessURL:  accessURL,
		refreshURL: refreshURL,
		credential: &ClientCredential{
			ClientID:     clientID,
			ClientSecret: clientSecret,
		},
	}
}
func APIClientFromConfig(config map[string]any) *APIClient {
	var timeout, maxIdleConns, maxPerHost int
	if v, ok := config["timeout"]; ok {
		timeout = v.(int)
	} else {
		timeout = 20
	}
	if v, ok := config["max_conn"]; ok {
		maxIdleConns = v.(int)
	} else {
		maxIdleConns = 10000
	}
	if v, ok := config["max_per_host"]; ok {
		maxPerHost = v.(int)
	} else {
		maxPerHost = 10000
	}
	return NewAPIClient(
		config["root_url"].(string),
		config["access_url"].(string),
		config["refresh_url"].(string),
		config["client_id"].(string),
		config["client_secret"].(string),
		timeout,
		maxIdleConns,
		maxPerHost,
	)
}
