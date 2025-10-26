/*
 * Copyright 2025 Holger de Carne
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package fritzsmarthome provides the necessary functions to access the FRITZ! Smart-Home-API.
package fritzsmarthome

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/tdrn-org/go-fritzsmarthome/api"
)

// ErrClientFailure indicates a system error while invoking the Smart-Home-API.
var ErrClientFailure = errors.New("client call failure")

// ErrAPIFailure indicates an API error while invoking the Smart-Home-API.
var ErrAPIFailure = errors.New("API failure")

type apiError struct {
	Code    int
	Message string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("%d %s", e.Code, e.Message)
}

// Client instances are used to access the Smart-Home-API via a given device.
type Client struct {
	baseURL       *url.URL
	user          string
	password      string
	httpClient    *http.Client
	apiClient     api.ClientWithResponsesInterface
	logger        *slog.Logger
	mutex         sync.RWMutex
	authorization string
}

// ClientOption interface is used to set Client options during Client creation.
type ClientOption interface {
	// Apply sets one or more options in the given Client instance.
	Apply(client *Client)
}

// ClientOptionFunc type is used to wrap functions into a ClientOption instance.
type ClientOptionFunc func(client *Client)

// Apply sets one or more options in the given Client instance.
func (f ClientOptionFunc) Apply(client *Client) {
	f(client)
}

// WithHttpClient sets a Client instance's [http.Client] which is used
// to access the Smart-Home-API device.
func WithHttpClient(httpClient *http.Client) ClientOptionFunc {
	return func(client *Client) {
		client.httpClient = httpClient
	}
}

// WithLogger sets a Client instance's [slog.Logger] which is used
// for logging.
func WithLogger(logger *slog.Logger) ClientOptionFunc {
	return func(client *Client) {
		client.logger = logger
	}
}

// NewClient creates a new Client instance using the given
// connect URL as well as Client options.
//
// Beside the actual URL to access the Smart-Home-API device
// the connect URL must also include the login credentials.
func NewClient(connectURL *url.URL, options ...ClientOption) (*Client, error) {
	baseURL := &url.URL{
		Scheme: connectURL.Scheme,
		Host:   connectURL.Host,
	}
	user := connectURL.User.Username()
	password, _ := connectURL.User.Password()
	client := &Client{
		baseURL:  baseURL,
		user:     user,
		password: password,
	}
	for _, option := range options {
		option.Apply(client)
	}
	if client.httpClient == nil {
		client.httpClient = &http.Client{}
	}
	if client.logger == nil {
		client.logger = slog.With(slog.String("client", baseURL.String()))
	}
	httpClientOption := func(apiClient *api.Client) error {
		apiClient.Client = client.httpClient
		return nil
	}
	apiURL := baseURL.JoinPath("api/v0")
	apiClient, err := api.NewClientWithResponses(apiURL.String(), httpClientOption)
	if err != nil {
		return nil, fmt.Errorf("failed to create client (cause: %w)", err)
	}
	client.apiClient = apiClient
	return client, nil
}

// BaseURL gets the base URL used to access the Smart-Home-API device.
//
// The base URL does not contain a path and no login credentials.
func (client *Client) BaseURL() *url.URL {
	return client.baseURL
}

func (client *Client) loginURL() *url.URL {
	loginURL := client.baseURL.JoinPath("/login_sid.lua")
	params := loginURL.Query()
	params.Add("version", "2")
	loginURL.RawQuery = params.Encode()
	return loginURL
}

// DeleteConfigurationDeviceByUID API call.
func (client *Client) DeleteConfigurationDeviceByUID(ctx context.Context, uid string) (*api.DeleteConfigurationDeviceByUIDResponse, error) {
	response, err := client.deleteConfigurationDeviceByUID(ctx, uid)
	if client.retryAfterAuthenticate(err) {
		response, err = client.deleteConfigurationDeviceByUID(ctx, uid)
	}
	return response, err
}

func (client *Client) deleteConfigurationDeviceByUID(ctx context.Context, uid string) (*api.DeleteConfigurationDeviceByUIDResponse, error) {
	response, err := client.apiClient.DeleteConfigurationDeviceByUIDWithResponse(ctx, uid, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// GetConfigurationDeviceByUID API call.
func (client *Client) GetConfigurationDeviceByUID(ctx context.Context, uid string) (*api.GetConfigurationDeviceByUIDResponse, error) {
	response, err := client.getConfigurationDeviceByUID(ctx, uid)
	if client.retryAfterAuthenticate(err) {
		response, err = client.getConfigurationDeviceByUID(ctx, uid)
	}
	return response, err
}

func (client *Client) getConfigurationDeviceByUID(ctx context.Context, uid string) (*api.GetConfigurationDeviceByUIDResponse, error) {
	response, err := client.apiClient.GetConfigurationDeviceByUIDWithResponse(ctx, uid, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// PutConfigurationDeviceByUID API call.
func (client *Client) PutConfigurationDeviceByUID(ctx context.Context, uid string, body api.PutConfigurationDeviceByUIDJSONRequestBody) (*api.PutConfigurationDeviceByUIDResponse, error) {
	response, err := client.putConfigurationDeviceByUID(ctx, uid, body)
	if client.retryAfterAuthenticate(err) {
		response, err = client.putConfigurationDeviceByUID(ctx, uid, body)
	}
	return response, err
}

func (client *Client) putConfigurationDeviceByUID(ctx context.Context, uid string, body api.PutConfigurationDeviceByUIDJSONRequestBody) (*api.PutConfigurationDeviceByUIDResponse, error) {
	response, err := client.apiClient.PutConfigurationDeviceByUIDWithResponse(ctx, uid, body, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// PostConfigurationGroupByName API call.
func (client *Client) PostConfigurationGroupByName(ctx context.Context, params *api.PostConfigurationGroupByNameParams, body api.PostConfigurationGroupByNameJSONRequestBody) (*api.PostConfigurationGroupByNameResponse, error) {
	response, err := client.postConfigurationGroupByName(ctx, params, body)
	if client.retryAfterAuthenticate(err) {
		response, err = client.postConfigurationGroupByName(ctx, params, body)
	}
	return response, err
}

func (client *Client) postConfigurationGroupByName(ctx context.Context, params *api.PostConfigurationGroupByNameParams, body api.PostConfigurationGroupByNameJSONRequestBody) (*api.PostConfigurationGroupByNameResponse, error) {
	response, err := client.apiClient.PostConfigurationGroupByNameWithResponse(ctx, params, body, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// DeleteConfigurationGroupByUID API call.
func (client *Client) DeleteConfigurationGroupByUID(ctx context.Context, uid string) (*api.DeleteConfigurationGroupByUIDResponse, error) {
	response, err := client.deleteConfigurationGroupByUID(ctx, uid)
	if client.retryAfterAuthenticate(err) {
		response, err = client.deleteConfigurationGroupByUID(ctx, uid)
	}
	return response, err
}

func (client *Client) deleteConfigurationGroupByUID(ctx context.Context, uid string) (*api.DeleteConfigurationGroupByUIDResponse, error) {
	response, err := client.apiClient.DeleteConfigurationGroupByUIDWithResponse(ctx, uid, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// GetConfigurationGroupByUID API call.
func (client *Client) GetConfigurationGroupByUID(ctx context.Context, uid string) (*api.GetConfigurationGroupByUIDResponse, error) {
	response, err := client.getConfigurationGroupByUID(ctx, uid)
	if client.retryAfterAuthenticate(err) {
		response, err = client.getConfigurationGroupByUID(ctx, uid)
	}
	return response, err
}

func (client *Client) getConfigurationGroupByUID(ctx context.Context, uid string) (*api.GetConfigurationGroupByUIDResponse, error) {
	response, err := client.apiClient.GetConfigurationGroupByUIDWithResponse(ctx, uid, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// PutConfigurationGroupByUID API call.
func (client *Client) PutConfigurationGroupByUID(ctx context.Context, uid string, body api.PutConfigurationGroupByUIDJSONRequestBody) (*api.PutConfigurationGroupByUIDResponse, error) {
	response, err := client.putConfigurationGroupByUID(ctx, uid, body)
	if client.retryAfterAuthenticate(err) {
		response, err = client.putConfigurationGroupByUID(ctx, uid, body)
	}
	return response, err
}

func (client *Client) putConfigurationGroupByUID(ctx context.Context, uid string, body api.PutConfigurationGroupByUIDJSONRequestBody) (*api.PutConfigurationGroupByUIDResponse, error) {
	response, err := client.apiClient.PutConfigurationGroupByUIDWithResponse(ctx, uid, body, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// GetConfigurationTemplateCapabilities API call.
func (client *Client) GetConfigurationTemplateCapabilities(ctx context.Context) (*api.GetConfigurationTemplateCapabilitiesResponse, error) {
	response, err := client.getConfigurationTemplateCapabilities(ctx)
	if client.retryAfterAuthenticate(err) {
		response, err = client.getConfigurationTemplateCapabilities(ctx)
	}
	return response, err
}

func (client *Client) getConfigurationTemplateCapabilities(ctx context.Context) (*api.GetConfigurationTemplateCapabilitiesResponse, error) {
	response, err := client.apiClient.GetConfigurationTemplateCapabilitiesWithResponse(ctx, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// GetConfigurationTemplateCapabilities API call.
func (client *Client) PostConfigurationTemplateByName(ctx context.Context, params *api.PostConfigurationTemplateByNameParams, body api.PostConfigurationTemplateByNameJSONRequestBody) (*api.PostConfigurationTemplateByNameResponse, error) {
	response, err := client.postConfigurationTemplateByName(ctx, params, body)
	if client.retryAfterAuthenticate(err) {
		response, err = client.postConfigurationTemplateByName(ctx, params, body)
	}
	return response, err
}

func (client *Client) postConfigurationTemplateByName(ctx context.Context, params *api.PostConfigurationTemplateByNameParams, body api.PostConfigurationTemplateByNameJSONRequestBody) (*api.PostConfigurationTemplateByNameResponse, error) {
	response, err := client.apiClient.PostConfigurationTemplateByNameWithResponse(ctx, params, body, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// DeleteConfigurationTemplateByUID API call.
func (client *Client) DeleteConfigurationTemplateByUID(ctx context.Context, uid string) (*api.DeleteConfigurationTemplateByUIDResponse, error) {
	response, err := client.deleteConfigurationTemplateByUID(ctx, uid)
	if client.retryAfterAuthenticate(err) {
		response, err = client.deleteConfigurationTemplateByUID(ctx, uid)
	}
	return response, err
}

func (client *Client) deleteConfigurationTemplateByUID(ctx context.Context, uid string) (*api.DeleteConfigurationTemplateByUIDResponse, error) {
	response, err := client.apiClient.DeleteConfigurationTemplateByUIDWithResponse(ctx, uid, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// DeleteConfigurationTemplateByUID API call.
func (client *Client) GetConfigurationTemplateByUID(ctx context.Context, uid string) (*api.GetConfigurationTemplateByUIDResponse, error) {
	response, err := client.getConfigurationTemplateByUID(ctx, uid)
	if client.retryAfterAuthenticate(err) {
		response, err = client.getConfigurationTemplateByUID(ctx, uid)
	}
	return response, err
}

func (client *Client) getConfigurationTemplateByUID(ctx context.Context, uid string) (*api.GetConfigurationTemplateByUIDResponse, error) {
	response, err := client.apiClient.GetConfigurationTemplateByUIDWithResponse(ctx, uid, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// PutConfigurationTemplateByUID API call.
func (client *Client) PutConfigurationTemplateByUID(ctx context.Context, uid string, body api.PutConfigurationTemplateByUIDJSONRequestBody) (*api.PutConfigurationTemplateByUIDResponse, error) {
	response, err := client.putConfigurationTemplateByUID(ctx, uid, body)
	if client.retryAfterAuthenticate(err) {
		response, err = client.putConfigurationTemplateByUID(ctx, uid, body)
	}
	return response, err
}

func (client *Client) putConfigurationTemplateByUID(ctx context.Context, uid string, body api.PutConfigurationTemplateByUIDJSONRequestBody) (*api.PutConfigurationTemplateByUIDResponse, error) {
	response, err := client.apiClient.PutConfigurationTemplateByUIDWithResponse(ctx, uid, body, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// GetConfigurationUnitByUID API call.
func (client *Client) GetConfigurationUnitByUID(ctx context.Context, uid string) (*api.GetConfigurationUnitByUIDResponse, error) {
	response, err := client.getConfigurationUnitByUID(ctx, uid)
	if client.retryAfterAuthenticate(err) {
		response, err = client.getConfigurationUnitByUID(ctx, uid)
	}
	return response, err
}

func (client *Client) getConfigurationUnitByUID(ctx context.Context, uid string) (*api.GetConfigurationUnitByUIDResponse, error) {
	response, err := client.apiClient.GetConfigurationUnitByUIDWithResponse(ctx, uid, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// PutConfigurationUnitByUID API call.
func (client *Client) PutConfigurationUnitByUID(ctx context.Context, uid string, body api.PutConfigurationUnitByUIDJSONRequestBody) (*api.PutConfigurationUnitByUIDResponse, error) {
	response, err := client.putConfigurationUnitByUID(ctx, uid, body)
	if client.retryAfterAuthenticate(err) {
		response, err = client.putConfigurationUnitByUID(ctx, uid, body)
	}
	return response, err
}

func (client *Client) putConfigurationUnitByUID(ctx context.Context, uid string, body api.PutConfigurationUnitByUIDJSONRequestBody) (*api.PutConfigurationUnitByUIDResponse, error) {
	response, err := client.apiClient.PutConfigurationUnitByUIDWithResponse(ctx, uid, body, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// PostInstallCodeBySerial API call.
func (client *Client) PostInstallCodeBySerial(ctx context.Context, serial string, body api.PostInstallCodeBySerialJSONRequestBody) (*api.PostInstallCodeBySerialResponse, error) {
	response, err := client.postInstallCodeBySerial(ctx, serial, body)
	if client.retryAfterAuthenticate(err) {
		response, err = client.postInstallCodeBySerial(ctx, serial, body)
	}
	return response, err
}

func (client *Client) postInstallCodeBySerial(ctx context.Context, serial string, body api.PostInstallCodeBySerialJSONRequestBody) (*api.PostInstallCodeBySerialResponse, error) {
	response, err := client.apiClient.PostInstallCodeBySerialWithResponse(ctx, serial, body, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// GetRadioBasesList API call.
func (client *Client) GetRadioBasesList(ctx context.Context) (*api.GetRadioBasesListResponse, error) {
	response, err := client.getRadioBasesList(ctx)
	if client.retryAfterAuthenticate(err) {
		response, err = client.getRadioBasesList(ctx)
	}
	return response, err
}

func (client *Client) getRadioBasesList(ctx context.Context) (*api.GetRadioBasesListResponse, error) {
	response, err := client.apiClient.GetRadioBasesListWithResponse(ctx, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// GetRadioBaseBySerial API call.
func (client *Client) GetRadioBaseBySerial(ctx context.Context, serial string) (*api.GetRadioBaseBySerialResponse, error) {
	response, err := client.getRadioBaseBySerial(ctx, serial)
	if client.retryAfterAuthenticate(err) {
		response, err = client.getRadioBaseBySerial(ctx, serial)
	}
	return response, err
}

func (client *Client) getRadioBaseBySerial(ctx context.Context, serial string) (*api.GetRadioBaseBySerialResponse, error) {
	response, err := client.apiClient.GetRadioBaseBySerialWithResponse(ctx, serial, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// PostResetCodeBySerial API call.
func (client *Client) PostResetCodeBySerial(ctx context.Context, serial string, body api.PostResetCodeBySerialJSONRequestBody) (*api.PostResetCodeBySerialResponse, error) {
	response, err := client.postResetCodeBySerial(ctx, serial, body)
	if client.retryAfterAuthenticate(err) {
		response, err = client.postResetCodeBySerial(ctx, serial, body)
	}
	return response, err
}

func (client *Client) postResetCodeBySerial(ctx context.Context, serial string, body api.PostResetCodeBySerialJSONRequestBody) (*api.PostResetCodeBySerialResponse, error) {
	response, err := client.apiClient.PostResetCodeBySerialWithResponse(ctx, serial, body, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// PostStartSubscriptionBySerial API call.
func (client *Client) PostStartSubscriptionBySerial(ctx context.Context, serial string, body api.PostStartSubscriptionBySerialJSONRequestBody) (*api.PostStartSubscriptionBySerialResponse, error) {
	response, err := client.postStartSubscriptionBySerial(ctx, serial, body)
	if client.retryAfterAuthenticate(err) {
		response, err = client.postStartSubscriptionBySerial(ctx, serial, body)
	}
	return response, err
}

func (client *Client) postStartSubscriptionBySerial(ctx context.Context, serial string, body api.PostStartSubscriptionBySerialJSONRequestBody) (*api.PostStartSubscriptionBySerialResponse, error) {
	response, err := client.apiClient.PostStartSubscriptionBySerialWithResponse(ctx, serial, body, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// PostStopSubscriptionBySerial API call.
func (client *Client) PostStopSubscriptionBySerial(ctx context.Context, serial string) (*api.PostStopSubscriptionBySerialResponse, error) {
	response, err := client.postStopSubscriptionBySerial(ctx, serial)
	if client.retryAfterAuthenticate(err) {
		response, err = client.postStopSubscriptionBySerial(ctx, serial)
	}
	return response, err
}

func (client *Client) postStopSubscriptionBySerial(ctx context.Context, serial string) (*api.PostStopSubscriptionBySerialResponse, error) {
	response, err := client.apiClient.PostStopSubscriptionBySerialWithResponse(ctx, serial, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// GetSubscriptionStateByUid API call.
func (client *Client) GetSubscriptionStateByUid(ctx context.Context, uid string) (*api.GetSubscriptionStateByUidResponse, error) {
	response, err := client.getSubscriptionStateByUid(ctx, uid)
	if client.retryAfterAuthenticate(err) {
		response, err = client.getSubscriptionStateByUid(ctx, uid)
	}
	return response, err
}

func (client *Client) getSubscriptionStateByUid(ctx context.Context, uid string) (*api.GetSubscriptionStateByUidResponse, error) {
	response, err := client.apiClient.GetSubscriptionStateByUidWithResponse(ctx, uid, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// GetOverview API call.
func (client *Client) GetOverview(ctx context.Context) (*api.GetOverviewResponse, error) {
	response, err := client.getOverview(ctx)
	if client.retryAfterAuthenticate(err) {
		response, err = client.getOverview(ctx)
	}
	return response, err
}

func (client *Client) getOverview(ctx context.Context) (*api.GetOverviewResponse, error) {
	response, err := client.apiClient.GetOverviewWithResponse(ctx, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// GetOverviewDevicesList API call.
func (client *Client) GetOverviewDevicesList(ctx context.Context) (*api.GetOverviewDevicesListResponse, error) {
	response, err := client.getOverviewDevicesList(ctx)
	if client.retryAfterAuthenticate(err) {
		response, err = client.getOverviewDevicesList(ctx)
	}
	return response, err
}

func (client *Client) getOverviewDevicesList(ctx context.Context) (*api.GetOverviewDevicesListResponse, error) {
	response, err := client.apiClient.GetOverviewDevicesListWithResponse(ctx, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// GetOverviewDeviceByUID API call.
func (client *Client) GetOverviewDeviceByUID(ctx context.Context, uid string) (*api.GetOverviewDeviceByUIDResponse, error) {
	response, err := client.getOverviewDeviceByUID(ctx, uid)
	if client.retryAfterAuthenticate(err) {
		response, err = client.getOverviewDeviceByUID(ctx, uid)
	}
	return response, err
}

func (client *Client) getOverviewDeviceByUID(ctx context.Context, uid string) (*api.GetOverviewDeviceByUIDResponse, error) {
	response, err := client.apiClient.GetOverviewDeviceByUIDWithResponse(ctx, uid, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// GetOverviewGlobals API call.
func (client *Client) GetOverviewGlobals(ctx context.Context) (*api.GetOverviewGlobalsResponse, error) {
	response, err := client.getOverviewGlobals(ctx)
	if client.retryAfterAuthenticate(err) {
		response, err = client.getOverviewGlobals(ctx)
	}
	return response, err
}

func (client *Client) getOverviewGlobals(ctx context.Context) (*api.GetOverviewGlobalsResponse, error) {
	response, err := client.apiClient.GetOverviewGlobalsWithResponse(ctx, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// GetOverviewGroupsList API call.
func (client *Client) GetOverviewGroupsList(ctx context.Context) (*api.GetOverviewGroupsListResponse, error) {
	response, err := client.getOverviewGroupsList(ctx)
	if client.retryAfterAuthenticate(err) {
		response, err = client.getOverviewGroupsList(ctx)
	}
	return response, err
}

func (client *Client) getOverviewGroupsList(ctx context.Context) (*api.GetOverviewGroupsListResponse, error) {
	response, err := client.apiClient.GetOverviewGroupsListWithResponse(ctx, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// GetOverviewGroupByUID API call.
func (client *Client) GetOverviewGroupByUID(ctx context.Context, uid string) (*api.GetOverviewGroupByUIDResponse, error) {
	response, err := client.getOverviewGroupByUID(ctx, uid)
	if client.retryAfterAuthenticate(err) {
		response, err = client.getOverviewGroupByUID(ctx, uid)
	}
	return response, err
}

func (client *Client) getOverviewGroupByUID(ctx context.Context, uid string) (*api.GetOverviewGroupByUIDResponse, error) {
	response, err := client.apiClient.GetOverviewGroupByUIDWithResponse(ctx, uid, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// GetOverviewTemplatesList API call.
func (client *Client) GetOverviewTemplatesList(ctx context.Context) (*api.GetOverviewTemplatesListResponse, error) {
	response, err := client.getOverviewTemplatesList(ctx)
	if client.retryAfterAuthenticate(err) {
		response, err = client.getOverviewTemplatesList(ctx)
	}
	return response, err
}

func (client *Client) getOverviewTemplatesList(ctx context.Context) (*api.GetOverviewTemplatesListResponse, error) {
	response, err := client.apiClient.GetOverviewTemplatesListWithResponse(ctx, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// GetOverviewTemplateByUID API call.
func (client *Client) GetOverviewTemplateByUID(ctx context.Context, uid string) (*api.GetOverviewTemplateByUIDResponse, error) {
	response, err := client.getOverviewTemplateByUID(ctx, uid)
	if client.retryAfterAuthenticate(err) {
		response, err = client.getOverviewTemplateByUID(ctx, uid)
	}
	return response, err
}

func (client *Client) getOverviewTemplateByUID(ctx context.Context, uid string) (*api.GetOverviewTemplateByUIDResponse, error) {
	response, err := client.apiClient.GetOverviewTemplateByUIDWithResponse(ctx, uid, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// PostOverviewTemplateByUID API call.
func (client *Client) PostOverviewTemplateByUID(ctx context.Context, uid string, body api.PostOverviewTemplateByUIDJSONRequestBody) (*api.PostOverviewTemplateByUIDResponse, error) {
	response, err := client.postOverviewTemplateByUID(ctx, uid, body)
	if client.retryAfterAuthenticate(err) {
		response, err = client.postOverviewTemplateByUID(ctx, uid, body)
	}
	return response, err
}

func (client *Client) postOverviewTemplateByUID(ctx context.Context, uid string, body api.PostOverviewTemplateByUIDJSONRequestBody) (*api.PostOverviewTemplateByUIDResponse, error) {
	response, err := client.apiClient.PostOverviewTemplateByUIDWithResponse(ctx, uid, body, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, nil)
}

// GetOverviewTriggersList API call.
func (client *Client) GetOverviewTriggersList(ctx context.Context) (*api.GetOverviewTriggersListResponse, error) {
	response, err := client.getOverviewTriggersList(ctx)
	if client.retryAfterAuthenticate(err) {
		response, err = client.getOverviewTriggersList(ctx)
	}
	return response, err
}

func (client *Client) getOverviewTriggersList(ctx context.Context) (*api.GetOverviewTriggersListResponse, error) {
	response, err := client.apiClient.GetOverviewTriggersListWithResponse(ctx, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// GetOverviewTriggerByUID API call.
func (client *Client) GetOverviewTriggerByUID(ctx context.Context, uid string) (*api.GetOverviewTriggerByUIDResponse, error) {
	response, err := client.getOverviewTriggerByUID(ctx, uid)
	if client.retryAfterAuthenticate(err) {
		response, err = client.getOverviewTriggerByUID(ctx, uid)
	}
	return response, err
}

func (client *Client) getOverviewTriggerByUID(ctx context.Context, uid string) (*api.GetOverviewTriggerByUIDResponse, error) {
	response, err := client.apiClient.GetOverviewTriggerByUIDWithResponse(ctx, uid, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// PutOverviewTriggerByUID API call.
func (client *Client) PutOverviewTriggerByUID(ctx context.Context, uid string, body api.PutOverviewTriggerByUIDJSONRequestBody) (*api.PutOverviewTriggerByUIDResponse, error) {
	response, err := client.putOverviewTriggerByUID(ctx, uid, body)
	if client.retryAfterAuthenticate(err) {
		response, err = client.putOverviewTriggerByUID(ctx, uid, body)
	}
	return response, err
}

func (client *Client) putOverviewTriggerByUID(ctx context.Context, uid string, body api.PutOverviewTriggerByUIDJSONRequestBody) (*api.PutOverviewTriggerByUIDResponse, error) {
	response, err := client.apiClient.PutOverviewTriggerByUIDWithResponse(ctx, uid, body, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// GetOverviewUnitsList API call.
func (client *Client) GetOverviewUnitsList(ctx context.Context) (*api.GetOverviewUnitsListResponse, error) {
	response, err := client.getOverviewUnitsList(ctx)
	if client.retryAfterAuthenticate(err) {
		response, err = client.getOverviewUnitsList(ctx)
	}
	return response, err
}

func (client *Client) getOverviewUnitsList(ctx context.Context) (*api.GetOverviewUnitsListResponse, error) {
	response, err := client.apiClient.GetOverviewUnitsListWithResponse(ctx, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// GetOverviewUnitByUID API call.
func (client *Client) GetOverviewUnitByUID(ctx context.Context, uid string) (*api.GetOverviewUnitByUIDResponse, error) {
	response, err := client.getOverviewUnitByUID(ctx, uid)
	if client.retryAfterAuthenticate(err) {
		response, err = client.getOverviewUnitByUID(ctx, uid)
	}
	return response, err
}

func (client *Client) getOverviewUnitByUID(ctx context.Context, uid string) (*api.GetOverviewUnitByUIDResponse, error) {
	response, err := client.apiClient.GetOverviewUnitByUIDWithResponse(ctx, uid, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

// PutOverviewUnitByUID API call.
func (client *Client) PutOverviewUnitByUID(ctx context.Context, uid string, body api.PutOverviewUnitByUIDJSONRequestBody) (*api.PutOverviewUnitByUIDResponse, error) {
	response, err := client.putOverviewUnitByUID(ctx, uid, body)
	if client.retryAfterAuthenticate(err) {
		response, err = client.putOverviewUnitByUID(ctx, uid, body)
	}
	return response, err
}

func (client *Client) putOverviewUnitByUID(ctx context.Context, uid string, body api.PutOverviewUnitByUIDJSONRequestBody) (*api.PutOverviewUnitByUIDResponse, error) {
	response, err := client.apiClient.PutOverviewUnitByUIDWithResponse(ctx, uid, body, client.authenticateRequest)
	if err != nil {
		return nil, client.wrapSystemError(err)
	}
	return response, client.checkAPIResponse(response.HTTPResponse, response.JSONDefault)
}

func (client *Client) authenticateRequest(ctx context.Context, request *http.Request) error {
	client.mutex.RLock()
	defer client.mutex.RUnlock()
	if client.authorization != "" {
		request.Header.Add(api.AuthorizationHeader, client.authorization)
	}
	return nil
}

func (client *Client) operationID() string {
	pc, _, _, _ := runtime.Caller(3)
	caller := runtime.FuncForPC(pc)
	callerName := caller.Name()
	return callerName[strings.LastIndex(callerName, ".")+1:]
}

func (client *Client) wrapSystemError(err error) error {
	return fmt.Errorf("%w %s (cause: %w)", ErrClientFailure, client.operationID(), err)
}

func (client *Client) checkAPIResponse(httpResponse *http.Response, apiResponse *api.ErrorResponse) error {
	if apiResponse != nil {
		apiErrList := *apiResponse.Errors
		apiErrs := make([]error, 0, len(apiErrList))
		for _, apiErr := range apiErrList {
			apiErrs = append(apiErrs, &apiError{Code: apiErr.Code, Message: *apiErr.Message})
		}
		if len(apiErrs) > 0 {
			return fmt.Errorf("%w %s (cause: %w)", ErrAPIFailure, client.operationID(), errors.Join(apiErrs...))
		}
	}
	if httpResponse.StatusCode != http.StatusOK {
		return fmt.Errorf("%w %s (status: %s)", ErrAPIFailure, client.operationID(), httpResponse.Status)

	}
	return nil
}

func (client *Client) retryAfterAuthenticate(apiStatus error) bool {
	apiErr := &apiError{}
	if !errors.As(apiStatus, &apiErr) {
		return false
	}
	if apiErr.Code != 3001 {
		return false
	}
	client.logger.Info("renewing session ID")
	sessionInfo := &sessionInfoResponse{}
	loginURL := client.loginURL()
	challengeRequest, err := http.NewRequest(http.MethodGet, loginURL.String(), nil)
	if err != nil {
		client.logger.Error("failed to prepare login challenge request", slog.Any("err", err))
		return false
	}
	err = client.getXML(challengeRequest, sessionInfo)
	if err != nil {
		client.logger.Error("failed to get login challenge", slog.Any("err", err))
		return false
	}
	if sessionInfo.BlockTime != 0 {
		client.logger.Error("login blocked", slog.Int("block_time", sessionInfo.BlockTime))
		return false
	}
	response, err := sessionInfo.challengeResponse(client.password)
	if err != nil {
		client.logger.Error("failed to generate login challenge response", slog.Any("err", err))
		return false
	}
	loginRequestBody := url.Values{}
	loginRequestBody.Add("username", client.user)
	loginRequestBody.Add("response", response)
	loginRequest, err := http.NewRequest(http.MethodPost, loginURL.String(), strings.NewReader(loginRequestBody.Encode()))
	loginRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		client.logger.Error("failed to prepare login request", slog.Any("err", err))
		return false
	}
	sessionInfo = &sessionInfoResponse{}
	err = client.getXML(loginRequest, sessionInfo)
	if err != nil {
		client.logger.Error("failed to request session ID", slog.Any("err", err))
		return false
	}
	client.mutex.Lock()
	defer client.mutex.Unlock()
	client.authorization = sessionInfo.authorization()
	client.logger.Info("session ID renewed")
	return true
}

func (client *Client) getXML(request *http.Request, doc any) error {
	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("failed to access URL '%s' (cause: %w)", request.URL.String(), err)
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get URL '%s' (status: %s)", request.URL.String(), response.Status)
	}
	responseBody := response.Body
	defer responseBody.Close()
	responseBytes, err := io.ReadAll(responseBody)
	if err != nil {
		return fmt.Errorf("failed to read URL '%s' (cause: %w)", request.URL.String(), err)
	}
	err = xml.Unmarshal(responseBytes, doc)
	if err != nil {
		return fmt.Errorf("failed to decode URL '%s' (cause: %w)", request.URL.String(), err)
	}
	return nil
}

type sessionInfoResponse struct {
	SID       string        `xml:"SID"`
	Challenge string        `xml:"Challenge"`
	BlockTime int           `xml:"BlockTime"`
	Rights    sessionRights `xml:"Rights"`
}

func (r *sessionInfoResponse) challengeResponse(password string) (string, error) {
	const unexpectedChallengeFormat = "unexpected challenge '%s'"
	const hashErrorFormat = "hash failure (cause: %w)"
	challengeParts := strings.Split(r.Challenge, "$")
	if len(challengeParts) != 5 || challengeParts[0] != "2" {
		return "", fmt.Errorf(unexpectedChallengeFormat, r.Challenge)
	}
	iter1, err := strconv.Atoi(challengeParts[1])
	if err != nil {
		return "", fmt.Errorf(unexpectedChallengeFormat, r.Challenge)
	}
	salt1, err := hex.DecodeString(challengeParts[2])
	if err != nil {
		return "", fmt.Errorf(unexpectedChallengeFormat, r.Challenge)
	}
	iter2, err := strconv.Atoi(challengeParts[3])
	if err != nil {
		return "", fmt.Errorf(unexpectedChallengeFormat, r.Challenge)
	}
	salt2, err := hex.DecodeString(challengeParts[4])
	if err != nil {
		return "", fmt.Errorf(unexpectedChallengeFormat, r.Challenge)
	}
	hash1, err := pbkdf2.Key(sha256.New, password, salt1, iter1, 32)
	if err != nil {
		return "", fmt.Errorf(hashErrorFormat, err)
	}
	hash2, err := pbkdf2.Key(sha256.New, string(hash1), salt2, iter2, 32)
	if err != nil {
		return "", fmt.Errorf(hashErrorFormat, err)
	}
	return fmt.Sprintf("%s$%x", challengeParts[4], hash2), nil
}

func (r *sessionInfoResponse) authorization() string {
	return "AVM-SID " + r.SID
}

type sessionRights struct {
	Name   []string `xml:"Name"`
	Access []int    `xml:"Access"`
}
