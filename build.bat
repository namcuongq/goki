@echo off
go build --ldflags="-s -w" --trimpath -gcflags=all="-l -B -wb=false" -o goki.exe .\main.go