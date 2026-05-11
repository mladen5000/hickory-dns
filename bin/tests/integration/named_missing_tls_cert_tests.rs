use std::{
    path::Path,
    process::{Command, Stdio},
    thread,
    time::Duration,
};

#[test]
fn missing_tls_cert_warning_is_emitted_by_server_startup() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("bin crate should have a workspace parent");
    let config = workspace_root.join("tests/test-data/test_configs/example.toml");
    let zonedir = workspace_root.join("tests/test-data/test_configs");

    let mut child = Command::new(env!("CARGO_BIN_EXE_hickory-dns"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .arg(format!("--config={}", config.display()))
        .arg(format!("--zonedir={}", zonedir.display()))
        .arg("--port=0")
        .spawn()
        .expect("failed to start hickory-dns");

    thread::sleep(Duration::from_secs(2));
    if child
        .try_wait()
        .expect("failed to poll hickory-dns")
        .is_none()
    {
        child.kill().expect("failed to kill hickory-dns");
    }

    let output = child
        .wait_with_output()
        .expect("failed to collect hickory-dns output");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("WARN")
            && stderr.contains(
                "TLS-family transports (DoT/DoH/DoQ) are compiled in and not all disabled"
            )
            && stderr.contains("no [tls_cert] is configured"),
        "expected missing tls_cert warning on stderr, got:\n{stderr}"
    );
}
