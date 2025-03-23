APP_NAME := simple-proxy
BINARY := bin/$(APP_NAME)

.PHONY: all build lint deploy clean

all: build

build:
    go build -o $(BINARY) .

lint:
    golangci-lint run

deploy: build
    @echo "Deploying $(BINARY) ..."
    # scp $(BINARY) user@yourserver.com:/path/to/deployment

clean:
    rm -f $(BINARY)