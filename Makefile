.PHONY: wasm wasm-node wasm-build wasm-nbis wasm-build-nbis cli vsix test all clean trust-report dist fixtures

# Drives wasm-bindgen-cli directly (skipping wasm-pack 0.14.0, which is broken
# against current Cargo). Install once:
#   cargo install wasm-bindgen-cli --version 0.2.121
WASM_OUT      := packages/pivlib/wasm
WASM_NODE_OUT := packages/pivlib/wasm-node
WASM_INPUT    := target/wasm32-unknown-unknown/release/pivlib.wasm

DIST          := dist/pivlib

# Default WASM build: no NBIS. Cert/CSR/CRL/key/PKCS#7/#12/CHUID/CCC/SecurityObject
# and the portrait pipeline all work. Fingerprint encoder returns a stub error.
# Use this for CI / web deploys — no WASI SDK required.
wasm-build:
	cargo build --release --target wasm32-unknown-unknown \
		-p pivlib --features wasm

wasm: wasm-build
	mkdir -p $(WASM_OUT)
	wasm-bindgen --target bundler --out-dir $(WASM_OUT) $(WASM_INPUT)

wasm-node: wasm-build
	mkdir -p $(WASM_NODE_OUT)
	wasm-bindgen --target nodejs --out-dir $(WASM_NODE_OUT) $(WASM_INPUT)
	@# wasm-bindgen --target nodejs emits CommonJS, but our package.json is
	@# `"type": "module"`. Drop a per-dir package.json so Node loads the
	@# generated file as CJS regardless of the outer package's setting.
	echo '{ "type": "commonjs" }' > $(WASM_NODE_OUT)/package.json

# Full WASM build including NBIS C (WSQ decode + mindtct minutiae extraction).
# Requires WASI SDK on the host — see CLAUDE.md §"Critical gotchas".
#   macOS:    brew install wasi-sdk
#   Manual:   https://github.com/WebAssembly/wasi-sdk/releases
#             then `export WASI_SDK_PATH=/opt/wasi-sdk`
wasm-build-nbis:
	cargo build --release --target wasm32-unknown-unknown \
		-p pivlib --features wasm,nbis

wasm-nbis: wasm-build-nbis
	mkdir -p $(WASM_OUT)
	wasm-bindgen --target bundler --out-dir $(WASM_OUT) $(WASM_INPUT)
	mkdir -p $(WASM_NODE_OUT)
	wasm-bindgen --target nodejs --out-dir $(WASM_NODE_OUT) $(WASM_INPUT)
	echo '{ "type": "commonjs" }' > $(WASM_NODE_OUT)/package.json

cli:
	cargo build --release -p pivlib_cli

vsix: wasm-node
	cd apps/vscode-extension && npm install && npm run package

test:
	cargo test --workspace

# Regenerate the synthetic demo corpus under tests/fixtures/.
# Each fixture is round-tripped through pivlib's parser as a smoke check —
# a parser regression that breaks a fixture surfaces here, not at web build time.
fixtures:
	cargo run -p pivlib_fixtures -- --out-dir tests/fixtures

all: wasm wasm-node cli

# Full-fat build: NBIS-bundled WASM (real WSQ decode/encode + mindtct minutiae).
# Used by `make dist` so production deploys ship the complete pipeline.
all-nbis: wasm-nbis cli

# Mirrors the netjson-diagrams dist layout. Uses the NBIS WASM so the deployed
# web demo can exercise the fingerprint encode/decode pipeline end-to-end.
dist: all-nbis
	rm -rf $(DIST)
	mkdir -p $(DIST)/cli $(DIST)/wasm $(DIST)/wasm-node $(DIST)/npm $(DIST)/web $(DIST)/vsix
	cp target/release/pivlib $(DIST)/cli/ 2>/dev/null || true
	cp -R $(WASM_OUT)/. $(DIST)/wasm/ 2>/dev/null || true
	cp -R $(WASM_NODE_OUT)/. $(DIST)/wasm-node/ 2>/dev/null || true
	-cd packages/pivlib && npm pack --pack-destination ../../$(DIST)/npm
	-cd apps/web && npm run build && cp -R dist/. ../../$(DIST)/web/
	-cd apps/vscode-extension && npm run package && cp -- *.vsix ../../$(DIST)/vsix/
	@echo
	@echo "Artifacts published to $(DIST):"
	@ls -1 $(DIST) 2>/dev/null

clean:
	cargo clean
	rm -rf $(WASM_OUT) $(WASM_NODE_OUT) packages/pivlib/dist
	rm -rf apps/vscode-extension/dist apps/vscode-extension/*.vsix
	rm -rf apps/web/dist
	rm -rf dist

trust-report:
	bash scripts/trust-report.sh
