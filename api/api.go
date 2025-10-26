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

package api

//go:generate go run ../cmd/build/build.go fetch https://fritz.support/resources/SmarthomeRestApiFRITZOS82.yaml smarthome.gen.yaml
//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen --config=oapi-codegen-smarthome.yaml smarthome.gen.yaml

import (
	_ "embed"
)

// The openhue-api spec yaml file used to generate the API code.
//
//go:embed smarthome.gen.yaml
var SmartHomeRestApiSpecYaml []byte

// The header key to use for authorization.
const AuthorizationHeader = "Authorization"
