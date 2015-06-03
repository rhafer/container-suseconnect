//
// Copyright (c) 2015 SUSE LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

var suseConnectLocations = []string{
	"/etc/SUSEConnect",
	"/run/secrets/SUSEConnect",
}

func ParseSUSEConnect(reader io.Reader) (string, error) {
	url := ""

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		// comments #
		if strings.IndexAny(scanner.Text(), "#-") == 0 {
			continue
		}

		// empty lines
		if scanner.Text() == "" {
			continue
		}

		parts := strings.SplitN(scanner.Text(), ":", 2)
		if len(parts) != 2 {
			return url, fmt.Errorf("Can't parse line: %v", scanner.Text())
		}
		if strings.Trim(parts[0], "\t ") == "url" {
			url = strings.Trim(parts[1], "\t ")
		}
	}

	if err := scanner.Err(); err != nil {
		return url, err
	}

	return url, nil
}

func ReadSUSEConnectUrl() (string, error) {
	var url string = ""
	var suseConnectPath string = ""
	for _, path := range suseConnectLocations {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		} else {
			suseConnectPath = path
			break
		}
	}

	if suseConnectPath == "" {
		return url, nil
	}

	file, err := os.Open(suseConnectPath)
	if err != nil {
		return url, fmt.Errorf("Can't open %s file: %v", suseConnectPath, err.Error())
	}
	defer file.Close()

	return ParseSUSEConnect(file)
}