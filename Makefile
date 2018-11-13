#BIN := $(shell basename $(CURDIR))
BIN := demo

all: test

clean:
	go clean .
	rm -f *.png *.out

test:
	go test .

$(BIN).wasm:
	GOOS=js GOARCH=wasm go build -o $@ .

wasm_exec.js:
	cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" .

