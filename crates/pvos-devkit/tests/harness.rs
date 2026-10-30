//! The harness against the kit's real programs: boot, owner, sign-in, a second
//! member, and what happens with no kit.

use std::path::Path;

use pvos_devkit::{view, wait_for, App, Instance, Kit};
use pvos_sdk::proto::{ProviderId, ServerToDesktop};
use serde_json::json;

/// The example, and the folder its manifest is in (gone when that is dropped).
fn greeter() -> (App, tempfile::TempDir) {
    // The worked example in this workspace, built before these tests by the
    // pipeline; its manifest is written here, as an app's own would be.
    let binary = std::env::var("PVOS_TEST_GREETER").expect("PVOS_TEST_GREETER names the built example");
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("manifest.json");
    std::fs::write(
        &manifest,
        json!({
            "id": "com.example.greeter",
            "version": "0.1.0",
            "api_version": 1,
            "display_name": "Greeter",
            "tier": "user",
            "residency": "integrated",
            "capabilities": { "required": [], "optional": [] },
            "services_provided": [{ "name": "greeter", "version": "1.0.0", "methods": ["greet"] }],
            "ui": { "surfaces": [{ "name": "main", "mode": "viewmodel" }] },
            "headless": false,
            "admin_only": false,
            "runtime": { "kind": "native", "entrypoint": "./greeter" }
        })
        .to_string(),
    )
    .unwrap();
    (App::new(binary, manifest), dir)
}

#[test]
fn an_app_runs_under_the_real_pvos() {
    let pvos = Instance::start().unwrap();
    let id = "com.example.greeter";
    let (greeter, _manifest) = greeter();
    pvos.install(&greeter).unwrap();
    pvos.start_app(id).unwrap();

    let owner = pvos.owner().unwrap();
    let provider = ProviderId(id.into());
    let mut answer = None;
    wait_for("the greeter to answer", || {
        answer = owner.call(&provider, "greeter", "greet", json!({ "name": "kit" })).ok();
        answer.is_some()
    });
    assert_eq!(answer.unwrap(), json!("hello kit"));

    let mut desktop = pvos.desktop().unwrap();
    desktop.open_surface(id, "main");
    let window = desktop.next_view(id, "main");
    assert_eq!(view::rows_of_table_with(&window, "name"), vec![vec!["kit".to_string(), "hello kit".to_string()]]);

    // Stopped means stopped: a call no longer reaches it.
    pvos.stop_app(id).unwrap();
    wait_for("the greeter to stop answering", || {
        owner.call(&provider, "greeter", "greet", json!({ "name": "gone" })).is_err()
    });
}

#[test]
fn nothing_is_granted_that_was_not_asked_for() {
    // The real broker is in the path: an app with no grant is refused.
    let pvos = Instance::start().unwrap();
    let id = "com.example.greeter";
    let (greeter, _manifest) = greeter();
    pvos.install(&greeter).unwrap();
    let (apps, grants) = pvos.owner().unwrap().admin_list().unwrap();
    assert!(apps.iter().any(|a| a.app_id == id), "installed");
    // Its own region is all it holds.
    let of_app: Vec<String> = grants.iter().map(|g| format!("{g:?}")).filter(|g| g.contains(id)).collect();
    assert_eq!(of_app.len(), 1, "{of_app:?}");
    assert!(of_app[0].contains("kind: Storage"), "{of_app:?}");
}

#[test]
fn a_second_member_signs_in_as_themselves() {
    let pvos = Instance::start().unwrap();
    let alice = pvos.add_member("alice").unwrap();
    let mut desktop = pvos.desktop_as(&alice).unwrap();
    desktop.action(pvos_sdk::proto::DesktopAction::NotificationList);
    desktop.recv_until("alice's notifications", |m| matches!(m, ServerToDesktop::Notifications { .. }).then_some(()));
    assert!(!desktop.token().is_empty());
}

#[test]
fn nothing_is_left_running_after_a_drop() {
    let mount = {
        let pvos = Instance::start().unwrap();
        pvos.mount().display().to_string()
    };
    wait_for("the programs to stop", || {
        let out = std::process::Command::new("pgrep").args(["-f", &mount]).output().unwrap();
        out.stdout.is_empty()
    });
}

#[test]
fn a_test_forest_serves_a_folder_to_who_it_should() {
    use pvos_devkit::{Region, TestForest};
    use pvos_sdk::keys::{crypto, identity};
    use pvos_sdk::pvfs::Client;

    let files = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(files.path().join("TV/Show")).unwrap();
    std::fs::write(files.path().join("TV/Show/one.mkv"), b"one").unwrap();

    let reader = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let pubkey = crypto::pubkey_bytes(&reader);
    let forest = TestForest::start(&[Region { folder: files.path(), members: &[(&pubkey, "r")] }]).unwrap();

    let mut client = Client::connect_signed(&forest.socket, &pubkey, |d| crypto::sign_digest(&reader, d).unwrap()).unwrap();
    assert_eq!(client.info().unwrap().forest_id, forest.forest_id);
    let entries = client.view_ls("TV/Show").unwrap();
    assert!(entries.iter().any(|e| e.rel_path.ends_with("one.mkv")), "{entries:?}");

    // Someone not enrolled reads nothing.
    let stranger = identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap();
    let denied = Client::connect_signed(&forest.socket, &crypto::pubkey_bytes(&stranger), |d| crypto::sign_digest(&stranger, d).unwrap())
        .and_then(|mut c| c.view_ls("TV/Show"));
    assert!(denied.map(|e| e.is_empty()).unwrap_or(true), "a stranger sees nothing");
}

#[test]
fn no_kit_says_how_to_get_one() {
    let empty = tempfile::tempdir().unwrap();
    let err = Kit::at(empty.path()).unwrap_err().to_string();
    assert!(err.contains("not a dev kit"), "{err}");
}

#[test]
fn a_kit_for_another_api_is_refused() {
    let kit = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(kit.path().join("bin")).unwrap();
    for name in ["pvosd", "pvfsd", "pvfs", "pvos"] {
        std::fs::write(Path::new(kit.path()).join("bin").join(name), "").unwrap();
    }
    std::fs::write(kit.path().join("VERSION"), "api_version=999\n").unwrap();
    let err = Kit::at(kit.path()).unwrap_err().to_string();
    assert!(err.contains("speaks PVOS API 999"), "{err}");
}
