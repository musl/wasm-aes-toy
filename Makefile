BIN := main.wasm

all: test

clean:
	go clean .
	rm -f *.png *.out *.wasm

test:
	go test .

run:
	GOOS=js GOARCH=wasm go run -exec="$(shell go env GOROOT)/misc/wasm/go_js_wasm_exec" .

$(BIN):
	GOOS=js GOARCH=wasm go build -o $@ .

wasm_exec.js:
	cp "$(shell go env GOROOT)/misc/wasm/wasm_exec.js" .

serve: wasm_exec.js $(BIN)
	go run tools/serve.go

