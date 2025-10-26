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

// Package mock provides a mock implementation of the Smart-Home-API for testing.
package mock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/tdrn-org/go-fritzsmarthome/api"
)

// Username defines the user name used for authentication towards a mock server.
const Username string = "fritz1337"

// Password defines the password used for authentication towards a mock server.
const Password string = "1example"

const loginPath string = "/login_sid.lua"

const mockSessionID string = "0123456789"

const mockAuthorization string = "AVM-SID " + mockSessionID

// Server represents a mock instance.
type Server struct {
	httpListener net.Listener
	connectURL   *url.URL
	logger       *slog.Logger
	stoppedWG    sync.WaitGroup
	httpServer   *http.Server
}

// Start starts and returns a new mock instance.
//
// Start panics in case of an error. The returned server
// is listening on localhost using a dynamic port.
func Start() *Server {
	httpListener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		log.Fatal(err)
	}
	address := httpListener.Addr().String()
	connectURL, err := url.Parse(fmt.Sprintf("http://%s:%s@%s", Username, Password, address))
	logger := slog.Default().With(slog.String("server", address))
	if err != nil {
		log.Fatal(err)
	}
	server := &Server{
		httpListener: httpListener,
		connectURL:   connectURL,
		logger:       logger,
	}
	server.setupHttpServer()
	server.stoppedWG.Go(server.listenAndServe)
	return server
}

// ConnectURL gets the connect URL for this mock instance.
func (s *Server) ConnectURL() *url.URL {
	return s.connectURL
}

// Stop stops this mock instance.
func (s *Server) Stop(ctx context.Context) {
	s.httpServer.Shutdown(ctx)
	s.stoppedWG.Wait()
}

func (s *Server) setupHttpServer() {
	baseRouter := http.NewServeMux()
	baseRouter.HandleFunc(loginPath, s.handleLogin)
	strictHandlerMiddlewares := []api.StrictMiddlewareFunc{
		s.logOperationMiddleware,
	}
	strictHandlerOptions := api.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  s.errorHandler,
		ResponseErrorHandlerFunc: s.errorHandler,
	}
	strictHandler := api.NewStrictHandlerWithOptions(s, strictHandlerMiddlewares, strictHandlerOptions)
	handlerMiddlewares := []api.MiddlewareFunc{
		s.checkAuthorization,
	}
	handlerOptions := api.StdHTTPServerOptions{
		BaseURL:          "/api/v0",
		BaseRouter:       baseRouter,
		Middlewares:      handlerMiddlewares,
		ErrorHandlerFunc: s.errorHandler,
	}
	handler := api.HandlerWithOptions(strictHandler, handlerOptions)
	s.httpServer = &http.Server{
		Handler: handler,
	}
}

func (s *Server) logOperationMiddleware(f api.StrictHandlerFunc, operationID string) api.StrictHandlerFunc {
	s.logger.Info("mock call", slog.String("operation", operationID))
	return f
}

func (s *Server) checkAuthorization(handler http.Handler) http.Handler {
	const permissionDeniedResponseFormat = `{"errors":[{"code":3001,"message":"permission denied: %s"}]}`
	handlerFunc := func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get(api.AuthorizationHeader)
		if authorization == mockAuthorization {
			handler.ServeHTTP(w, r)
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, permissionDeniedResponseFormat, r.URL.Path)
		}
	}
	return http.HandlerFunc(handlerFunc)
}

func (s *Server) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusInternalServerError)
}

func (s *Server) listenAndServe() {
	s.logger.Info("http server starting...")
	err := s.httpServer.Serve(s.httpListener)
	if !errors.Is(err, http.ErrServerClosed) {
		s.logger.Error("http server failure", slog.Any("err", err))
		return
	}
	s.logger.Info("http server stopped")
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleLoginChallenge(w, r)
	case http.MethodPost:
		s.handleLoginResponse(w, r)
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (s *Server) handleLoginChallenge(w http.ResponseWriter, _ *http.Request) {
	const sessionInfo = `
	<SessionInfo>
		<SID>0000000000000000</SID>
		<Challenge>2$10000$5A1711$2000$5A1722</Challenge>
		<BlockTime>0</BlockTime><Rights/>
		<Users>
			<User>%s</User>
		</Users>
		<Rights/>
	</SessionInfo>`
	w.Header().Set("Content-Type", "text/xml")
	fmt.Fprintf(w, sessionInfo, Username)
}

func (s *Server) handleLoginResponse(w http.ResponseWriter, _ *http.Request) {
	const sessionInfo = `
	<SessionInfo>
		<SID>%s</SID>
		<BlockTime>0</BlockTime><Rights/>
		<Users>
			<User>%s</User>
		</Users>
		<Rights>
			<Name>NAS</Name>
			<Access>2</Access>
			<Name>App</Name>
			<Access>2</Access>
			<Name>HomeAuto</Name>
			<Access>2</Access>
			<Name>BoxAdmin</Name>
			<Access>2</Access>
			<Name>Phone</Name>
			<Access>2</Access>
		</Rights>
	</SessionInfo>`
	w.Header().Set("Content-Type", "text/xml")
	fmt.Fprintf(w, sessionInfo, mockSessionID, Username)
}

// Delete device by UID
// (DELETE /smarthome/configuration/devices/{UID})
func (s *Server) DeleteConfigurationDeviceByUID(ctx context.Context, request api.DeleteConfigurationDeviceByUIDRequestObject) (api.DeleteConfigurationDeviceByUIDResponseObject, error) {
	return nil, nil
}

// Get device configuration by UID
// (GET /smarthome/configuration/devices/{UID})
func (s *Server) GetConfigurationDeviceByUID(ctx context.Context, request api.GetConfigurationDeviceByUIDRequestObject) (api.GetConfigurationDeviceByUIDResponseObject, error) {
	return nil, nil
}

// Configure and control device by UID
// (PUT /smarthome/configuration/devices/{UID})
func (s *Server) PutConfigurationDeviceByUID(ctx context.Context, request api.PutConfigurationDeviceByUIDRequestObject) (api.PutConfigurationDeviceByUIDResponseObject, error) {
	return nil, nil
}

// Create new group
// (POST /smarthome/configuration/groups)
func (s *Server) PostConfigurationGroupByName(ctx context.Context, request api.PostConfigurationGroupByNameRequestObject) (api.PostConfigurationGroupByNameResponseObject, error) {
	return nil, nil
}

// Delete group by UID
// (DELETE /smarthome/configuration/groups/{UID})
func (s *Server) DeleteConfigurationGroupByUID(ctx context.Context, request api.DeleteConfigurationGroupByUIDRequestObject) (api.DeleteConfigurationGroupByUIDResponseObject, error) {
	return nil, nil
}

// Get group configuration by UID
// (GET /smarthome/configuration/groups/{UID})
func (s *Server) GetConfigurationGroupByUID(ctx context.Context, request api.GetConfigurationGroupByUIDRequestObject) (api.GetConfigurationGroupByUIDResponseObject, error) {
	return nil, nil
}

// Configure and control group by UID
// (PUT /smarthome/configuration/groups/{UID})
func (s *Server) PutConfigurationGroupByUID(ctx context.Context, request api.PutConfigurationGroupByUIDRequestObject) (api.PutConfigurationGroupByUIDResponseObject, error) {
	return nil, nil
}

// Get possible template configuration capabilities
// (GET /smarthome/configuration/templateCapabilities)
func (s *Server) GetConfigurationTemplateCapabilities(ctx context.Context, request api.GetConfigurationTemplateCapabilitiesRequestObject) (api.GetConfigurationTemplateCapabilitiesResponseObject, error) {
	return nil, nil
}

// Create new template
// (POST /smarthome/configuration/templates)
func (s *Server) PostConfigurationTemplateByName(ctx context.Context, request api.PostConfigurationTemplateByNameRequestObject) (api.PostConfigurationTemplateByNameResponseObject, error) {
	return nil, nil
}

// Delete template by UID
// (DELETE /smarthome/configuration/templates/{UID})
func (s *Server) DeleteConfigurationTemplateByUID(ctx context.Context, request api.DeleteConfigurationTemplateByUIDRequestObject) (api.DeleteConfigurationTemplateByUIDResponseObject, error) {
	return nil, nil
}

// Get template configuration by UID
// (GET /smarthome/configuration/templates/{UID})
func (s *Server) GetConfigurationTemplateByUID(ctx context.Context, request api.GetConfigurationTemplateByUIDRequestObject) (api.GetConfigurationTemplateByUIDResponseObject, error) {
	return nil, nil
}

// Configure and control template by UID
// (PUT /smarthome/configuration/templates/{UID})
func (s *Server) PutConfigurationTemplateByUID(ctx context.Context, request api.PutConfigurationTemplateByUIDRequestObject) (api.PutConfigurationTemplateByUIDResponseObject, error) {
	return nil, nil
}

// Get unit configuration by UID
// (GET /smarthome/configuration/units/{UID})
func (s *Server) GetConfigurationUnitByUID(ctx context.Context, request api.GetConfigurationUnitByUIDRequestObject) (api.GetConfigurationUnitByUIDResponseObject, error) {
	return nil, nil
}

// Configure and control unit by UID
// (PUT /smarthome/configuration/units/{UID})
func (s *Server) PutConfigurationUnitByUID(ctx context.Context, request api.PutConfigurationUnitByUIDRequestObject) (api.PutConfigurationUnitByUIDResponseObject, error) {
	return nil, nil
}

// Set installCode on zigbee radioBase
// (POST /smarthome/connect/installCode/{serial})
func (s *Server) PostInstallCodeBySerial(ctx context.Context, request api.PostInstallCodeBySerialRequestObject) (api.PostInstallCodeBySerialResponseObject, error) {
	return nil, nil
}

// Get list of radioBases
// (GET /smarthome/connect/radioBases)
func (s *Server) GetRadioBasesList(ctx context.Context, request api.GetRadioBasesListRequestObject) (api.GetRadioBasesListResponseObject, error) {
	return nil, nil
}

// Get radioBase by Serial
// (GET /smarthome/connect/radioBases/{serial})
func (s *Server) GetRadioBaseBySerial(ctx context.Context, request api.GetRadioBaseBySerialRequestObject) (api.GetRadioBaseBySerialResponseObject, error) {
	return nil, nil
}

// Set resetCode on zigbee radioBase
// (POST /smarthome/connect/resetCode/{serial})
func (s *Server) PostResetCodeBySerial(ctx context.Context, request api.PostResetCodeBySerialRequestObject) (api.PostResetCodeBySerialResponseObject, error) {
	return nil, nil
}

// Start Subscription on radioBase by Serial
// (POST /smarthome/connect/startSubscription/{serial})
func (s *Server) PostStartSubscriptionBySerial(ctx context.Context, request api.PostStartSubscriptionBySerialRequestObject) (api.PostStartSubscriptionBySerialResponseObject, error) {
	return nil, nil
}

// Stop Subscription on radioBase by Serial
// (POST /smarthome/connect/stopSubscription/{serial})
func (s *Server) PostStopSubscriptionBySerial(ctx context.Context, request api.PostStopSubscriptionBySerialRequestObject) (api.PostStopSubscriptionBySerialResponseObject, error) {
	return nil, nil
}

// Get subscription state by UID
// (GET /smarthome/connect/subscriptionState/{UID})
func (s *Server) GetSubscriptionStateByUid(ctx context.Context, request api.GetSubscriptionStateByUidRequestObject) (api.GetSubscriptionStateByUidResponseObject, error) {
	return nil, nil
}

// Get all overview infos and lists
// (GET /smarthome/overview)
func (s *Server) GetOverview(ctx context.Context, request api.GetOverviewRequestObject) (api.GetOverviewResponseObject, error) {
	response := api.GetOverview200JSONResponse{}
	err := s.readResponse(&response)
	return response, err
}

// Get list of devices
// (GET /smarthome/overview/devices)
func (s *Server) GetOverviewDevicesList(ctx context.Context, request api.GetOverviewDevicesListRequestObject) (api.GetOverviewDevicesListResponseObject, error) {
	response := api.GetOverviewDevicesList200JSONResponse{}
	err := s.readResponse(&response)
	return response, err
}

// Get device by UID
// (GET /smarthome/overview/devices/{UID})
func (s *Server) GetOverviewDeviceByUID(ctx context.Context, request api.GetOverviewDeviceByUIDRequestObject) (api.GetOverviewDeviceByUIDResponseObject, error) {
	return nil, nil
}

// Get smart home global values
// (GET /smarthome/overview/globals)
func (s *Server) GetOverviewGlobals(ctx context.Context, request api.GetOverviewGlobalsRequestObject) (api.GetOverviewGlobalsResponseObject, error) {
	response := api.GetOverviewGlobals200JSONResponse{}
	err := s.readResponse(&response)
	return response, err
}

// Get list of groups
// (GET /smarthome/overview/groups)
func (s *Server) GetOverviewGroupsList(ctx context.Context, request api.GetOverviewGroupsListRequestObject) (api.GetOverviewGroupsListResponseObject, error) {
	response := api.GetOverviewGroupsList200JSONResponse{}
	err := s.readResponse(&response)
	return response, err
}

// Get group by UID
// (GET /smarthome/overview/groups/{UID})
func (s *Server) GetOverviewGroupByUID(ctx context.Context, request api.GetOverviewGroupByUIDRequestObject) (api.GetOverviewGroupByUIDResponseObject, error) {
	return nil, nil
}

// Get list of templates
// (GET /smarthome/overview/templates)
func (s *Server) GetOverviewTemplatesList(ctx context.Context, request api.GetOverviewTemplatesListRequestObject) (api.GetOverviewTemplatesListResponseObject, error) {
	return nil, nil
}

// Get template by UID
// (GET /smarthome/overview/templates/{UID})
func (s *Server) GetOverviewTemplateByUID(ctx context.Context, request api.GetOverviewTemplateByUIDRequestObject) (api.GetOverviewTemplateByUIDResponseObject, error) {
	return nil, nil
}

// Applies a template by UID
// (POST /smarthome/overview/templates/{UID})
func (s *Server) PostOverviewTemplateByUID(ctx context.Context, request api.PostOverviewTemplateByUIDRequestObject) (api.PostOverviewTemplateByUIDResponseObject, error) {
	return nil, nil
}

// Get list of triggers
// (GET /smarthome/overview/triggers)
func (s *Server) GetOverviewTriggersList(ctx context.Context, request api.GetOverviewTriggersListRequestObject) (api.GetOverviewTriggersListResponseObject, error) {
	return nil, nil
}

// Get trigger by UID
// (GET /smarthome/overview/triggers/{UID})
func (s *Server) GetOverviewTriggerByUID(ctx context.Context, request api.GetOverviewTriggerByUIDRequestObject) (api.GetOverviewTriggerByUIDResponseObject, error) {
	return nil, nil
}

// Activate or deactivate trigger by UID
// (PUT /smarthome/overview/triggers/{UID})
func (s *Server) PutOverviewTriggerByUID(ctx context.Context, request api.PutOverviewTriggerByUIDRequestObject) (api.PutOverviewTriggerByUIDResponseObject, error) {
	return nil, nil
}

// Get list of units
// (GET /smarthome/overview/units)
func (s *Server) GetOverviewUnitsList(ctx context.Context, request api.GetOverviewUnitsListRequestObject) (api.GetOverviewUnitsListResponseObject, error) {
	return nil, nil
}

// Get unit by UID
// (GET /smarthome/overview/units/{UID})
func (s *Server) GetOverviewUnitByUID(ctx context.Context, request api.GetOverviewUnitByUIDRequestObject) (api.GetOverviewUnitByUIDResponseObject, error) {
	return nil, nil
}

// Control interfaces for unit by UID
// (PUT /smarthome/overview/units/{UID})
func (s *Server) PutOverviewUnitByUID(ctx context.Context, request api.PutOverviewUnitByUIDRequestObject) (api.PutOverviewUnitByUIDResponseObject, error) {
	return nil, nil
}

func (s *Server) readResponse(response any) error {
	pc, _, _, _ := runtime.Caller(1)
	caller := runtime.FuncForPC(pc)
	callerName := caller.Name()
	operationID := callerName[strings.LastIndex(callerName, ".")+1:]
	responseFile := filepath.Join("testdata", operationID+".json")
	responseData, err := os.ReadFile(responseFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(responseData, response)
}
