#!/bin/bash
#
# Find gogoprotobuf at https://code.google.com/p/gogoprotobuf/
#
# Install gogoprotobuf using :
#    go get code.google.com/p/gogoprotobuf/{proto,protoc-gen-gogo,gogoproto}
#
exec protoc --proto_path=$GOPATH/src:. --gogo_out=. $*
