/*
 * Copyright (C) 2025-2026 Holger de Carne
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

package fritzsmarthome_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-fritzsmarthome"
	"github.com/tdrn-org/go-fritzsmarthome/api"
	"github.com/tdrn-org/go-fritzsmarthome/mock"
)

const MockDir string = "mock/testdata"

type RecordConfig struct {
	Enabled    bool   `json:"enabled"`
	ConnectURL string `json:"connect_url"`
	Record     bool   `json:"record"`
}

func TestNoAPI(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	client, err := fritzsmarthome.NewClient(serverURL)
	require.NoError(t, err)

	response, err := client.GetOverview(t.Context())
	require.ErrorIs(t, err, fritzsmarthome.ErrAPIFailure)
	require.NotNil(t, response)
	require.Nil(t, response.JSONDefault)
	require.Nil(t, response.JSON200)
}

func TestInvalidAPI(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v0/smarthome/overview", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Ok"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	client, err := fritzsmarthome.NewClient(serverURL)
	require.NoError(t, err)

	response, err := client.GetOverview(t.Context())
	require.ErrorIs(t, err, fritzsmarthome.ErrAPIFailure)
	require.NotNil(t, response)
	require.Nil(t, response.JSONDefault)
	require.Nil(t, response.JSON200)
}

func TestNotAuthorized(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v0/smarthome/overview", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		message := "unauthorized"
		errors := api.ErrorList{
			{
				Code:    3001,
				Message: &message,
			},
		}
		response := &api.ErrorResponse{
			Errors: &errors,
		}
		err := json.NewEncoder(w).Encode(response)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	client, err := fritzsmarthome.NewClient(serverURL)
	require.NoError(t, err)

	response, err := client.GetOverview(t.Context())
	require.ErrorIs(t, err, fritzsmarthome.ErrAPIFailure)
	require.NotNil(t, response)
	require.NotNil(t, response.JSONDefault)
	require.Nil(t, response.JSON200)
}

func TestClient(t *testing.T) {
	var connectURL *url.URL
	record := false

	configData, err := os.ReadFile("record.conf")
	if err == nil {
		config := &RecordConfig{}
		err = json.Unmarshal(configData, config)
		require.NoError(t, err)
		if config.Enabled {
			connectURL, err = url.Parse(config.ConnectURL)
			require.NoError(t, err)
			record = config.Record
		}
	}
	if connectURL == nil {
		serverMock := mock.Start(MockDir)
		defer serverMock.Stop(t.Context())
		connectURL = serverMock.ConnectURL()
	}

	client, err := fritzsmarthome.NewClient(connectURL)
	require.NoError(t, err)

	t.Run("GetConfigurationTemplateCapabilities", func(t *testing.T) {
		testGetConfigurationTemplateCapabilities(t, client, record)
	})
	t.Run("GetRadioBasesList", func(t *testing.T) {
		testGetRadioBasesList(t, client, record)
	})
	t.Run("GetOverview", func(t *testing.T) {
		testGetOverview(t, client, record)
	})
	t.Run("GetOverviewDevicesList", func(t *testing.T) {
		testGetOverviewDevicesList(t, client, record)
	})
	t.Run("GetOverviewGlobals", func(t *testing.T) {
		testGetOverviewGlobals(t, client, record)
	})
	t.Run("GetOverviewGroupsList", func(t *testing.T) {
		testGetOverviewGroupsList(t, client, record)
	})
	t.Run("GetOverviewTemplatesList", func(t *testing.T) {
		testGetOverviewTemplatesList(t, client, record)
	})
	t.Run("GetOverviewTriggersList", func(t *testing.T) {
		testGetOverviewTriggersList(t, client, record)
	})
	t.Run("GetOverviewUnitsList", func(t *testing.T) {
		testGetOverviewUnitsList(t, client, record)
	})

	masqueradeResponses(t, record)
}

func testGetConfigurationTemplateCapabilities(t *testing.T, client *fritzsmarthome.Client, record bool) {
	response, err := client.GetConfigurationTemplateCapabilities(t.Context())
	require.NoError(t, err)
	recordResponse(t, response.JSON200, record)
	require.NotNil(t, response)
}

func testGetRadioBasesList(t *testing.T, client *fritzsmarthome.Client, record bool) {
	response, err := client.GetRadioBasesList(t.Context())
	require.NoError(t, err)
	recordResponse(t, response.JSON200, record)
	require.NotNil(t, response)
}

func testGetOverview(t *testing.T, client *fritzsmarthome.Client, record bool) {
	response, err := client.GetOverview(t.Context())
	require.NoError(t, err)
	recordResponse(t, response.JSON200, record)
	require.NotNil(t, response)
}

func testGetOverviewDevicesList(t *testing.T, client *fritzsmarthome.Client, record bool) {
	response, err := client.GetOverviewDevicesList(t.Context())
	require.NoError(t, err)
	recordResponse(t, response.JSON200, record)
	require.NotNil(t, response)
}

func testGetOverviewGlobals(t *testing.T, client *fritzsmarthome.Client, record bool) {
	response, err := client.GetOverviewGlobals(t.Context())
	require.NoError(t, err)
	recordResponse(t, response.JSON200, record)
	require.NotNil(t, response)
}

func testGetOverviewGroupsList(t *testing.T, client *fritzsmarthome.Client, record bool) {
	response, err := client.GetOverviewGroupsList(t.Context())
	require.NoError(t, err)
	recordResponse(t, response.JSON200, record)
	require.NotNil(t, response)
}

func testGetOverviewTemplatesList(t *testing.T, client *fritzsmarthome.Client, record bool) {
	response, err := client.GetOverviewTemplatesList(t.Context())
	require.NoError(t, err)
	recordResponse(t, response.JSON200, record)
	require.NotNil(t, response)
}

func testGetOverviewTriggersList(t *testing.T, client *fritzsmarthome.Client, record bool) {
	response, err := client.GetOverviewTriggersList(t.Context())
	require.NoError(t, err)
	recordResponse(t, response.JSON200, record)
	require.NotNil(t, response)
}

func testGetOverviewUnitsList(t *testing.T, client *fritzsmarthome.Client, record bool) {
	response, err := client.GetOverviewUnitsList(t.Context())
	require.NoError(t, err)
	recordResponse(t, response.JSON200, record)
	require.NotNil(t, response)
}

func recordResponse(t *testing.T, response any, record bool) {
	if !record {
		return
	}
	dataFile := filepath.Join(MockDir, filepath.Base(t.Name())+".json")
	data, err := json.MarshalIndent(response, "  ", "  ")
	require.NoError(t, err)
	err = os.WriteFile(dataFile, data, 0660)
	require.NoError(t, err)
}

func masqueradeResponses(t *testing.T, record bool) {
	if !record {
		return
	}
	dirEntries, err := os.ReadDir(MockDir)
	require.NoError(t, err)
	m := &masquerader{
		nameAliases: make(map[string]string),
	}
	for _, dirEntry := range dirEntries {
		if !dirEntry.Type().IsRegular() || !strings.HasSuffix(dirEntry.Name(), ".json") {
			continue
		}
		dataFile := filepath.Join("testdata", dirEntry.Name())
		dataBytes, err := os.ReadFile(dataFile)
		require.NoError(t, err)
		var data any
		err = json.Unmarshal(dataBytes, &data)
		require.NoError(t, err)
		m.Masquerade(&data)
		dataBytes, err = json.MarshalIndent(data, "  ", "  ")
		require.NoError(t, err)
		err = os.WriteFile(dataFile, dataBytes, 0660)
		require.NoError(t, err)
	}
}

type masquerader struct {
	nameAliases map[string]string
}

func (m *masquerader) Masquerade(data any) {
	m.masquerade(reflect.ValueOf(data))
}

func (m *masquerader) masquerade(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			m.masquerade(v.Elem())
		}
	case reflect.Interface:
		if !v.IsNil() {
			m.masquerade(v.Elem())
		}
	case reflect.Map:
		m.masqueradeMap(v)
	case reflect.Slice:
		m.masqueradeSliceOrArray(v)
	}
}

func (m *masquerader) masqueradeMap(mapValue reflect.Value) {
	keyValues := mapValue.MapKeys()
	for _, keyValue := range keyValues {
		v := mapValue.MapIndex(keyValue)
		if v.Kind() == reflect.Interface && !v.IsNil() {
			v = v.Elem()
		}
		switch v.Kind() {
		case reflect.String:
			m.masqueradeMapIndex(mapValue, keyValue, v)
		default:
			m.masquerade(v)
		}
	}
}

func (m *masquerader) masqueradeMapIndex(mapValue, keyValue, v reflect.Value) {
	switch keyValue.String() {
	case "name":
		mapValue.SetMapIndex(keyValue, reflect.ValueOf(m.nameAlias(v.String())))
	}
}

func (m *masquerader) masqueradeSliceOrArray(p reflect.Value) {
	arrayLen := p.Len()
	for arrayIndex := range arrayLen {
		arrayElement := p.Index(arrayIndex)
		m.masquerade(arrayElement)
	}
}

func (m *masquerader) nameAlias(name string) string {
	alias := m.nameAliases[name]
	if alias == "" {
		alias = fmt.Sprintf("Name#%d", len(m.nameAliases)+1)
		m.nameAliases[name] = alias
	}
	return alias
}
