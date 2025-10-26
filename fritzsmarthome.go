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

// ErrClientFailure indicates a system error while invoking the client.
var ErrClientFailure = errors.New("client call failure")

var ErrLoginFailure = errors.New("login failure")

// ErrAPIFailure indicates an API call has failed with an API error.
var ErrAPIFailure = errors.New("API failure")

type APIError struct {
	Code    int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%d %s", e.Code, e.Message)
}

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

type ClientOption interface {
	Apply(client *Client)
}

type ClientOptionFunc func(client *Client)

func (f ClientOptionFunc) Apply(client *Client) {
	f(client)
}

func WithHttpClient(httpClient *http.Client) ClientOptionFunc {
	return func(client *Client) {
		client.httpClient = httpClient
	}
}

func WithLogger(logger *slog.Logger) ClientOptionFunc {
	return func(client *Client) {
		client.logger = logger
	}
}

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

func (client *Client) GetConfigurationGroupByUID(ctx context.Context, uid string) (*api.GetConfigurationGroupByUIDResponse, error) {
	return nil, nil
}

func (client *Client) PutConfigurationGroupByUID(ctx context.Context, uid string, body api.PutConfigurationGroupByUIDJSONRequestBody) (*api.PutConfigurationGroupByUIDResponse, error) {
	return nil, nil
}

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

func (client *Client) PostConfigurationTemplateByName(ctx context.Context, params *api.PostConfigurationTemplateByNameParams, body api.PostConfigurationTemplateByNameJSONRequestBody) (*api.PostConfigurationTemplateByNameResponse, error) {
	return nil, nil
}

func (client *Client) DeleteConfigurationTemplateByUID(ctx context.Context, uid string) (*api.DeleteConfigurationTemplateByUIDResponse, error) {
	return nil, nil
}

func (client *Client) GetConfigurationTemplateByUID(ctx context.Context, uid string) (*api.GetConfigurationTemplateByUIDResponse, error) {
	return nil, nil
}

func (client *Client) PutConfigurationTemplateByUID(ctx context.Context, uid string, body api.PutConfigurationTemplateByUIDJSONRequestBody) (*api.PutConfigurationTemplateByUIDResponse, error) {
	return nil, nil
}

func (client *Client) GetConfigurationUnitByUID(ctx context.Context, uid string) (*api.GetConfigurationUnitByUIDResponse, error) {
	return nil, nil
}

func (client *Client) PutConfigurationUnitByUID(ctx context.Context, uid string, body api.PutConfigurationUnitByUIDJSONRequestBody) (*api.PutConfigurationUnitByUIDResponse, error) {
	return nil, nil
}

func (client *Client) PostInstallCodeBySerial(ctx context.Context, serial string, body api.PostInstallCodeBySerialJSONRequestBody) (*api.PostInstallCodeBySerialResponse, error) {
	return nil, nil
}

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

func (client *Client) GetRadioBaseBySerial(ctx context.Context, serial string) (*api.GetRadioBaseBySerialResponse, error) {
	return nil, nil
}

func (client *Client) PostResetCodeBySerial(ctx context.Context, serial string, body api.PostResetCodeBySerialJSONRequestBody) (*api.PostResetCodeBySerialResponse, error) {
	return nil, nil
}

func (client *Client) PostStartSubscriptionBySerial(ctx context.Context, serial string, body api.PostStartSubscriptionBySerialJSONRequestBody) (*api.PostStartSubscriptionBySerialResponse, error) {
	return nil, nil
}

func (client *Client) PostStopSubscriptionBySerial(ctx context.Context, serial string) (*api.PostStopSubscriptionBySerialResponse, error) {
	return nil, nil
}

func (client *Client) GetSubscriptionStateByUid(ctx context.Context, uid string) (*api.GetSubscriptionStateByUidResponse, error) {
	return nil, nil
}

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

func (client *Client) GetOverviewDeviceByUID(ctx context.Context, uid string) (*api.GetOverviewDeviceByUIDResponse, error) {
	return nil, nil
}

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

func (client *Client) GetOverviewGroupByUID(ctx context.Context, uid string) (*api.GetOverviewGroupByUIDResponse, error) {
	return nil, nil
}

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

func (client *Client) GetOverviewTemplateByUID(ctx context.Context, uid string) (*api.GetOverviewTemplateByUIDResponse, error) {
	return nil, nil
}

func (client *Client) PostOverviewTemplateByUID(ctx context.Context, uid string, body api.PostOverviewTemplateByUIDJSONRequestBody) (*api.PostOverviewTemplateByUIDResponse, error) {
	return nil, nil
}

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

func (client *Client) GetOverviewTriggerByUID(ctx context.Context, uid string) (*api.GetOverviewTriggerByUIDResponse, error) {
	return nil, nil
}

func (client *Client) PutOverviewTriggerByUID(ctx context.Context, uid string, body api.PutOverviewTriggerByUIDJSONRequestBody) (*api.PutOverviewTriggerByUIDResponse, error) {
	return nil, nil
}

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

func (client *Client) GetOverviewUnitByUID(ctx context.Context, uid string) (*api.GetOverviewUnitByUIDResponse, error) {
	return nil, nil
}

func (client *Client) PutOverviewUnitByUID(ctx context.Context, uid string, body api.PutOverviewUnitByUIDJSONRequestBody) (*api.PutOverviewUnitByUIDResponse, error) {
	return nil, nil
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
		apiErrorList := *apiResponse.Errors
		apiErrors := make([]error, 0, len(apiErrorList))
		for _, apiError := range apiErrorList {
			apiErrors = append(apiErrors, &APIError{Code: apiError.Code, Message: *apiError.Message})
		}
		if len(apiErrors) > 0 {
			return fmt.Errorf("%w %s (cause: %w)", ErrAPIFailure, client.operationID(), errors.Join(apiErrors...))
		}
	}
	if httpResponse.StatusCode != http.StatusOK {
		return fmt.Errorf("%w %s (status: %s)", ErrAPIFailure, client.operationID(), httpResponse.Status)

	}
	return nil
}

func (client *Client) retryAfterAuthenticate(apiStatus error) bool {
	apiError := &APIError{}
	if !errors.As(apiStatus, &apiError) {
		return false
	}
	if apiError.Code != 3001 {
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
