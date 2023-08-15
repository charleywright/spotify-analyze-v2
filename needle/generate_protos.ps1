echo "Couldn't get this to work on Windows"

# Remove-Item -Recurse -Force .\src\proto
# New-Item -Path src -Name proto -ItemType Directory | Out-Null
# $files = Get-ChildItem -Path .\proto\ -Recurse -File -Filter *.proto
# foreach ($file in $files)
# {
#   protoc "--plugin=$pwd\node_modules\.bin\protoc-gen-ts_proto.cmd" "--ts_proto_out=$pwd\src\proto\" '--ts_proto_opt=esModuleInterop=true' "--proto_path=$pwd" "$file"
# }
