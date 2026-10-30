//! `pvos-dev new` writes an app that builds, and whose own end-to-end test passes
//! against the kit. This is what a stranger gets from their first command.

use std::path::Path;
use std::process::Command;

fn pvos_dev() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pvos-dev"))
}

#[test]
fn a_new_app_passes_its_own_test() {
    let dir = tempfile::tempdir().unwrap();
    let app = dir.path().join("hello-world");
    let sdk = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = pvos_dev()
        .args(["new", "--name", "Hello World", "--id", "com.example.helloworld", "--dir"])
        .arg(&app)
        .arg("--sdk-path")
        .arg(&sdk)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    for file in ["Cargo.toml", "manifest.json", "src/main.rs", "tests/end_to_end.rs", ".github/workflows/ci.yml", ".devcontainer/devcontainer.json"] {
        assert!(app.join(file).exists(), "{file} written");
    }

    // Its own target folder under the workspace's, so the SDK isn't built twice over.
    let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/template-app");
    let test = Command::new("cargo")
        .arg("test")
        .current_dir(&app)
        .env("CARGO_TARGET_DIR", &target)
        .output()
        .unwrap();
    assert!(
        test.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&test.stdout),
        String::from_utf8_lossy(&test.stderr)
    );
}

#[test]
fn new_refuses_a_name_that_cannot_be_a_crate() {
    let dir = tempfile::tempdir().unwrap();
    let out = pvos_dev()
        .args(["new", "--name", "123", "--id", "com.example.x", "--dir"])
        .arg(dir.path().join("x"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("does not start with a letter"));
}

#[test]
fn off_a_terminal_it_prints_the_usage_and_exits_2() {
    let out = pvos_dev().stdin(std::process::Stdio::null()).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Usage: pvos-dev"));
}
