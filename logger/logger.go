// Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package logger

import (
	"fmt"
	"os"

	log "github.com/cihub/seelog"
)

const (
	envLogLevel    = "VPC_CNI_LOG_LEVEL"
	envLogFilePath = "VPC_CNI_LOG_FILE"

	logConfigFormat = `
<seelog type="asyncloop" minlevel="%s">
 <outputs formatid="main">
  <rollingfile filename="%s" type="date" datepattern="2006-01-02-15" archivetype="none" maxrolls="24" />
 </outputs>
 <formats>
  <format id="main" format="%%UTCDate(2006-01-02T15:04:05Z07:00) [%%LEVEL] %%Msg%%n" />
 </formats>
</seelog>
`
)

// Setup sets up a file logger.
func Setup(logFilePath string) {
	config := fmt.Sprintf(logConfigFormat, getLogLevel(), getLogFilePath(logFilePath))

	logger, err := log.LoggerFromConfigAsString(config)
	if err != nil {
		fmt.Println("Error setting up logger: ", err)
		return
	}

	log.ReplaceLogger(logger)
}

// GetLogLevel returns the effective log level.
func getLogLevel() string {
	seelogLevel, ok := log.LogLevelFromString(os.Getenv(envLogLevel))
	if !ok {
		seelogLevel = log.InfoLvl
	}

	return seelogLevel.String()
}

// GetLogFilePath returns the effective log file path.
func getLogFilePath(defaultLogFilePath string) string {
	logFilePath := os.Getenv(envLogFilePath)
	if logFilePath == "" {
		logFilePath = defaultLogFilePath
	}

	return logFilePath
}
