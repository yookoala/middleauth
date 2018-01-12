#!/usr/bin/env bash

if [ "$(which gin)" == "" ]; then
	echo "! gin is not found in your enviornment !"
	echo
	echo "Suggestions:"
	echo "1. properly setup \$GOPATH/bin in your \$PATH"
	echo "2. use \`go get github.com/codegangsta/gin\` to install gin"
	echo
	exit 1
fi

# start example server with gin
gin --bin example-server --build ./cmd/example-server --port 8080 --immediate run
