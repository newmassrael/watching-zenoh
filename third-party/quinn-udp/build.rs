use cfg_aliases::cfg_aliases;

fn main() {
    // Setup cfg aliases
    cfg_aliases! {
        // Platforms
        apple: {
            any(
                target_os = "macos",
                target_os = "ios",
                target_os = "tvos",
                target_os = "visionos"
            )
        },
        bsd: {
            any(
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd"
            )
        },
        solarish: {
            any(
                target_os = "solaris",
                target_os = "illumos"
            )
        },
        // WZ PATCH: QNX with the io-pkt network stack (`target_env` nto70 and nto71). Its headers
        // have no IP_RECVTOS; io-sock (nto71_iosock, nto80) has it.
        nto_iopkt: {
            all(
                target_os = "nto",
                any(target_env = "nto70", target_env = "nto71")
            )
        },
        // Convenience aliases
        apple_fast: { all(apple, feature = "fast-apple-datapath") },
        apple_slow: { all(apple, not(feature = "fast-apple-datapath")) },
        wasm_browser: { all(target_family = "wasm", target_os = "unknown") },
    }
}
