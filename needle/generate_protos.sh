#!/bin/bash
rm -Rf src/proto
mkdir src/proto
# protoc --plugin=./node_modules/.bin/protoc-gen-ts --ts_out=src/proto --proto_path=./proto ./proto/**/*.proto ./proto/*.proto
# find src/proto -type f | xargs -I {} sed -i '1s/^/\/\/ @ts-nocheck\n/' {}
protoc --plugin=./node_modules/.bin/protoc-gen-ts_proto --ts_proto_out=src/proto '--ts_proto_opt=esModuleInterop=true' --proto_path=./proto ./proto/**/*.proto ./proto/*.proto
