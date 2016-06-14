#!/bin/bash
#
protoc --proto_path=$GOPATH/src:. --go_out=. $*
#
# We must replace :
# import protos "github.com/agl/pond/protos"
# by : import protos "github.com/agl/pond/protos/pond.pb"
#
perl -p -i~ -e 's/(import protos \"github.com\/agl\/pond\/protos)\/pond.pb\"/$1\"/' disk/client.pb.go 

