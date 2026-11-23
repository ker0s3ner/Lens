// Lens plugin example. Copy this file to the Lens plugins directory.
// Keep compatibility checks at the top when using newer API features.
fn on_open() {
    if script_api_version() < 1 {
        print("Lens script API is too old");
    } else {
        let large = 0;
        for f in functions() {
            if f.size > 4096 {
                print(`${hex(f.addr)} ${f.name}: ${f.size} bytes`);
                large += 1;
            }
        }
        print(`${large} large functions`);
    }
}
