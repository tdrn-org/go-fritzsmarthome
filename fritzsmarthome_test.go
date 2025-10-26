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

package fritzsmarthome_test

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-fritzsmarthome"
	"github.com/tdrn-org/go-fritzsmarthome/mock"
)

type RecordConfig struct {
	Enabled    bool   `json:"enabled"`
	ConnectURL string `json:"connect_url"`
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
			record = true
		}
	}
	if connectURL == nil {
		serverMock := mock.Start()
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
	dataFile := filepath.Join("testdata", filepath.Base(t.Name())+".json")
	_, err := os.Stat(dataFile)
	if errors.Is(err, os.ErrNotExist) {
		data, err := json.MarshalIndent(response, "  ", "  ")
		require.NoError(t, err)
		err = os.WriteFile(dataFile, data, 0660)
		require.NoError(t, err)
	}
}
