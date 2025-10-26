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

package mock_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-fritzsmarthome/mock"
)

func TestStartStop(t *testing.T) {
	serverMock := mock.Start()
	defer serverMock.Stop(t.Context())

	connectURL := serverMock.ConnectURL()
	require.Equal(t, mock.Username, connectURL.User.Username())
	password, set := connectURL.User.Password()
	require.True(t, set)
	require.Equal(t, mock.Password, password)
}
