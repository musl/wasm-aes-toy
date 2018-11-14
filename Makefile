BIN := main.wasm

.PHONY: all build clean run test

all: test

clean:
	go clean .
	rm -f *.png *.out *.wasm
	rm -fr build

test:
	go test .

run:
	GOOS=js GOARCH=wasm go run -exec="$(shell go env GOROOT)/misc/wasm/go_js_wasm_exec" .

$(BIN):
	GOOS=js GOARCH=wasm go build -o $@ .

build: clean $(BIN)
	mkdir -p build
	cp "$(shell go env GOROOT)/misc/wasm/wasm_exec.js" build/
	cp static/* build/
	cp $(BIN) build/

serve: build
	go run tools/serve.go

