.PHONY: build test race linux
build:
	go build -o bin/tunnel-lab ./cmd/tunnel-lab
test:
	go test ./... -count=1 -timeout=120s
race:
	go test -race ./... -count=1 -timeout=180s
linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/tunnel-lab-linux-amd64 ./cmd/tunnel-lab
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/tunnel-lab-linux-arm64 ./cmd/tunnel-lab
