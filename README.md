# Extism Rust PDK Plugin

See more documentation at https://github.com/extism/rust-pdk and
[join us on Discord](https://extism.org/discord) for more help.


# Compile command:
cargo build --target wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --release

# Test plugin
## Infos
extism call target/wasm32-unknown-unknown/debug/rust_pdk_template.wasm infos

## Process

extism call target/wasm32-unknown-unknown/debug/rust_pdk_template.wasm greet --input "Benjamin"
Get-Content -Raw -Path .\processinput.json | extism call target\wasm32-unknown-unknown\debug\redseat_plugin_torbox.wasm --allow-host '*' --log-level=info --wasi process --stdin

Get-Content -Raw -Path .\lookupinput.json | extism call target\wasm32-unknown-unknown\debug\redseat_plugin_torbox.wasm --allow-host '*' --log-level=info --wasi lookup --stdin