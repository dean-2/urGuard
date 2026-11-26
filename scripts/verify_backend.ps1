$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '../backend')
try {
    go build ./cmd/controlplane ./cmd/node ./cmd/urguard-cli
    if ($LASTEXITCODE) { exit $LASTEXITCODE }
    go vet ./...
    if ($LASTEXITCODE) { exit $LASTEXITCODE }
    go test -race -v -count=1 ./...
    if ($LASTEXITCODE) { exit $LASTEXITCODE }
    go test '-bench=.' '-benchtime=100ms' ./pkg/pqc/...
    if ($LASTEXITCODE) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}
