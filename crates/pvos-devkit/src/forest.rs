use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use tempfile::TempDir;

use crate::kit::Kit;
use crate::Result;

/// A folder to serve as one catalogue region of a [`TestForest`], and who may use it.
pub struct Region<'a> {
    pub folder: &'a Path,
    /// Each reader's public key and its rights, as `pvfs acl set` takes them (`r`, `rw`).
    pub members: &'a [(&'a [u8], &'a str)],
}

/// A forest with catalogue regions over folders of your own, served by the kit's
/// real `pvfsd`: for an app that reads forests itself, with no PVOS in the way.
pub struct TestForest {
    pub forest_id: String,
    /// `pvfsd`'s socket.
    pub socket: PathBuf,
    daemon: Child,
    _dir: TempDir,
}

impl TestForest {
    pub fn start(regions: &[Region]) -> Result<TestForest> {
        crate::kit::refuse_root()?;
        let kit = Kit::find()?;
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        let mount = root.join("forest");
        let sockets = root.join("sockets");
        std::fs::create_dir_all(&sockets)?;
        let pvfs = |args: &[&str]| -> Result<String> {
            let mut command = Command::new(kit.bin("pvfs"));
            command.arg("--data-dir").arg(mount.join(".pvfs"));
            forest_env(&mut command, root);
            let out = command.args(args).stdin(Stdio::null()).output()?;
            if !out.status.success() {
                return Err(format!("pvfs {args:?}: {}", String::from_utf8_lossy(&out.stderr)).into());
            }
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        };

        let mut init = Command::new(kit.bin("pvfs"));
        forest_env(&mut init, root);
        let out = init.args(["--json", "forest", "init", "--mount"]).arg(&mount).stdin(Stdio::null()).output()?;
        if !out.status.success() {
            return Err(format!("pvfs forest init: {}", String::from_utf8_lossy(&out.stderr)).into());
        }
        let identity: serde_json::Value = serde_json::from_slice(&out.stdout)
            .map_err(|e| format!("pvfs forest init --json: {e}"))?;
        let forest_id = identity["forest_id"].as_str().ok_or("no forest_id")?.to_string();
        let root_node = identity["root_node_id"].as_str().ok_or("no root_node_id")?.to_string();

        let mut enrolled: Vec<String> = Vec::new();
        for (n, region) in regions.iter().enumerate() {
            let node = pvfs(&["add", &root_node, "--kind", "folder", "--label", &format!("Library {n}")])?;
            pvfs(&["region", "mark", &node, "--catalogue"])?;
            let folder = region.folder.to_str().ok_or("a folder whose path is not text")?;
            pvfs(&["bind", &node, folder, "--hash-policy", "on_add"])?;
            pvfs(&["scan", &node])?;
            for (key, rights) in region.members {
                let key = hex::encode(key);
                if !enrolled.contains(&key) {
                    pvfs(&["device", "authorize-member", "--pubkey", &key])?;
                    enrolled.push(key.clone());
                }
                pvfs(&["acl", "set", &node, &format!("key:{key}"), rights])?;
            }
        }

        let mut serve = Command::new(kit.bin("pvfsd"));
        forest_env(&mut serve, root);
        crate::instance::die_with_this_process(&mut serve);
        let log = std::fs::File::create(root.join("pvfsd.log"))?;
        let daemon = serve
            .arg("--mount")
            .arg(&mount)
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()?;
        let find_socket = || -> Option<PathBuf> {
            std::fs::read_dir(&sockets).ok()?.find_map(|e| {
                let p = e.ok()?.path();
                (p.extension()? == "sock").then_some(p)
            })
        };
        if !crate::instance::wait(Duration::from_secs(20), || find_socket().is_some()) {
            let log = std::fs::read_to_string(root.join("pvfsd.log")).unwrap_or_default();
            return Err(format!("pvfsd did not come up:\n{log}").into());
        }
        let socket = find_socket().expect("just found");
        Ok(TestForest { forest_id, socket, daemon, _dir: dir })
    }
}

impl Drop for TestForest {
    fn drop(&mut self) {
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}

fn forest_env(command: &mut Command, root: &Path) {
    command
        .env("PVFS_REGISTRY_DIR", root.join("registry"))
        .env("PVFS_SOCKET_DIR", root.join("sockets"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("HOME", root);
}
