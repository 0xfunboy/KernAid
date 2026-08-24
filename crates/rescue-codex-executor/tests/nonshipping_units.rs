#![cfg(all(target_os = "linux", feature = "experimental-codex-exec"))]

const SOCKET: &str = include_str!("../../../rescue/codex/systemd/kernaid-rescue-codex.socket");
const SERVICE: &str = include_str!("../../../rescue/codex/systemd/kernaid-rescue-codex@.service");
const SHIPPING_SYSUSERS: &str =
    include_str!("../../../rescue/live-build/config/includes.chroot/etc/sysusers.d/kernaid.conf");
const SHIPPING_BUILD: &str = include_str!("../../../tools/build-rescue/build.sh");
const SHIPPING_HOOK: &str =
    include_str!("../../../rescue/live-build/config/hooks/live/0100-kernaid-safety.hook.chroot");
const CRATE_MANIFEST: &str = include_str!("../Cargo.toml");

fn source_lines(source: &str) -> Vec<&str> {
    source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

#[test]
fn socket_is_single_seqpacket_accept_template_and_has_no_install_surface() {
    let lines = source_lines(SOCKET);
    assert!(lines.contains(&"ListenSequentialPacket=/run/kernaid-rescue-codex.sock"));
    assert!(lines.contains(&"Accept=yes"));
    assert!(lines.contains(&"MaxConnections=1"));
    assert!(lines.contains(&"SocketGroup=kernaid-provider-client"));
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.starts_with("Listen"))
            .count(),
        1
    );
    assert!(!lines.contains(&"[Install]"));
    assert!(!SOCKET.contains("WantedBy="));
}

#[test]
fn source_units_are_feature_gated_offline_and_exactly_named_for_cgroup_tree() {
    let socket = source_lines(SOCKET);
    let service = source_lines(SERVICE);
    for lines in [&socket, &service] {
        assert!(lines.contains(&"ConditionKernelCommandLine=boot=live"));
        assert!(lines.contains(&"ConditionKernelCommandLine=kernaid.experimental_codex_exec=1"));
        assert!(lines.contains(&"ConditionFileIsExecutable=/usr/lib/kernaid/codex"));
        assert!(!lines.contains(&"[Install]"));
    }
    assert!(SERVICE.contains("kernaid-rescue-codex.socket"));
    assert!(!SERVICE.contains("kernaid-rescue-codex-auth"));
    assert!(service.contains(&"User=kernaid-codex"));
    assert!(service.contains(&"Group=kernaid-codex"));
    assert!(service.contains(&"SupplementaryGroups=kernaid-vault"));
    assert!(service.contains(&"RuntimeDirectory=kernaid-rescue-codex-%i"));
    assert!(service.contains(&"RuntimeDirectoryMode=0700"));
    assert!(service.contains(&"RuntimeMaxSec=145s"));
    assert!(service.contains(&"Delegate=pids"));
    assert!(service.contains(&"DelegateSubgroup=agent"));
    assert!(service.contains(&"KillMode=control-group"));
    assert!(service.contains(&"PrivateNetwork=yes"));
    assert!(service.contains(&"RestrictAddressFamilies=AF_UNIX"));
    assert!(
        service.contains(&"InaccessiblePaths=-/etc/codex -/run/kernaid-rescue-openai-egress.sock")
    );
    assert!(service.contains(&"StandardOutput=null"));
    assert!(service.contains(&"StandardError=null"));
    assert!(!SERVICE.contains("codex login"));

    let sysusers = source_lines(SHIPPING_SYSUSERS);
    assert!(sysusers.contains(&"g kernaid-codex 1003 -"));
    assert!(sysusers.contains(
        &"u kernaid-codex 1003:1003 \"KernAid Rescue Codex executor\" /nonexistent /usr/sbin/nologin"
    ));
    assert!(
        !sysusers
            .iter()
            .any(|line| line.starts_with("m kernaid-codex "))
    );
}

#[test]
fn source_units_are_not_present_in_the_shipping_live_image_tree() {
    assert!(CRATE_MANIFEST.contains("default = []"));
    assert!(CRATE_MANIFEST.contains("required-features = [\"experimental-codex-exec\"]"));
    let shipping = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../rescue/live-build/config/includes.chroot/etc/systemd/system");
    for unit in [
        "kernaid-rescue-codex.socket",
        "kernaid-rescue-codex@.service",
    ] {
        assert!(!shipping.join(unit).exists(), "{unit} unexpectedly ships");
    }
    for shipping_source in [SHIPPING_BUILD, SHIPPING_HOOK] {
        assert!(!shipping_source.contains("kernaid-rescue-codex-executor"));
        assert!(!shipping_source.contains("kernaid-rescue-codex.socket"));
    }
}
