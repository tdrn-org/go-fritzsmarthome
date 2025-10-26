//go:build tools
// +build tools

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

package main

import (
	"io"
	"log"
	"net/http"
	"os"
)

// Used via go:generate to perform build tasks.
func main() {
	switch os.Args[1] {
	case "fetch":
		fetch()
	}
}

// fetch external file
func fetch() {
	rsp, err := http.Get(os.Args[2])
	if err != nil {
		log.Fatal("download failure: ", err)
	}
	defer rsp.Body.Close()
	file, err := os.Create(os.Args[3])
	if err != nil {
		log.Fatal("create file failure: ", err)
	}
	defer file.Close()
	_, err = io.Copy(file, rsp.Body)
	if err != nil {
		log.Fatal("write file failure: ", err)
	}
}
