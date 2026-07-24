fn main() {
    // Emits the macOS/Linux dynamic-lookup link args so the cdylib's undefined
    // N-API symbols (napi_register_module_v1 et al.) resolve against the host at
    // load time, and generates the addon registration glue.
    napi_build::setup();
}
