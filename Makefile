.PHONY: build test check

build:
	go build -o bin/commonroom-worker ./cmd/commonroom-worker

test:
	go test -parallel 8 -timeout 60s ./...

check:
	gofmt -l . | (! grep .)
	go vet ./...
	go test -race -parallel 8 -timeout 90s ./...
