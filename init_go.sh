#!/bin/bash

go mod init github.com/iafilius/InternetQualityMonitor
go mod tidy
go build -o iqmon ./src