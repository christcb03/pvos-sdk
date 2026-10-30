use std::ffi::OsString;
use std::fs::File;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pvos_sdk::keys::identity::{self, DeviceKeyCache, SigningKey};
use pvos_sdk::keys::{acl, crypto};
use pvos_sdk::proto::{CapKind, Capability, Depth, DesktopToServer, ProviderId, Scope, ServiceSel, Subject, UiFile};
use pvos_sdk::AppConn;
use tempfile::TempDir;

use crate::desktop::Desktop;
use crate::kit::Kit;
use crate::Result;

/// A running PVOS, made for one test and gone when this is dropped.
pub struct Instance {
    kit: Kit,
    dir: TempDir,
    mount: PathBuf,
    control: PathBuf,
    pvfsd_socket: PathBuf,
    http_addr: String,
    owner_key: DeviceKeyCache,
    owner: Option<Member>,
    /// One attached owner, shared: pvosd knows a connection by who it is, so a second
    /// `@owner` closing would take the first one's replies with it.
    owner_conn: Mutex<Option<Arc<AppConn>>>,
    children: Vec<Child>,
}

/// Someone paired with this PVOS, holding throwaway keys.
#[derive(Clone)]
pub struct Member {
    pub name: String,
    pub identity: Arc<SigningKey>,
    pub encryption: Arc<SigningKey>,
    pub companion_socket: PathBuf,
}

impl Member {
    /// This member saying yes at their companion to a `RelayRequest`: the frame the
    /// page sends back. A paired owner's approvals (consent, an owner mutation) come
    /// this way, as they do in a browser.
    pub fn approve(&self, relay_id: u64, payload: &str) -> Result<DesktopToServer> {
        crate::desktop::approve_relay(&self.identity, relay_id, payload)
    }
}

/// An app to install: its binary and manifest, and its `ui/` if it has one.
#[derive(Clone, Debug)]
pub struct App {
    binary: PathBuf,
    manifest: PathBuf,
    ui: Option<PathBuf>,
}

/// The kit's real companion, for a person at a terminal: `pvos-dev run` uses it so
/// the browser's sign-in and approvals work, asking at that terminal.
pub struct RealCompanion {
    pub socket: PathBuf,
    pub web_addr: String,
}

impl App {
    /// A `ui/` folder beside the manifest is picked up by itself.
    pub fn new(binary: impl AsRef<Path>, manifest: impl AsRef<Path>) -> App {
        let manifest = manifest.as_ref().to_path_buf();
        let ui = manifest.parent().map(|d| d.join("ui")).filter(|d| d.is_dir());
        App { binary: binary.as_ref().to_path_buf(), manifest, ui }
    }

    /// Use this `ui/` folder.
    pub fn with_ui(mut self, ui: impl AsRef<Path>) -> App {
        self.ui = Some(ui.as_ref().to_path_buf());
        self
    }
}

impl Instance {
    /// Start a PVOS with an owner paired, using the kit [`Kit::find`] finds.
    ///
    /// Programs inherit this process's environment as it is now, so a test can put
    /// a fake tool on `PATH` first.
    pub fn start() -> Result<Instance> {
        Instance::start_with_owner("owner")
    }

    /// [`Instance::start`], with the owner paired under this member name.
    pub fn start_with_owner(name: &str) -> Result<Instance> {
        let mut instance = Instance::boot_in(Kit::find()?, tempfile::tempdir()?, None)?;
        instance.owner = Some(instance.add_member(name)?);
        Ok(instance)
    }

    /// Start a PVOS that uses the kit's real companion, which asks at this terminal.
    /// Nobody is paired yet: call [`Instance::pair_real_companion`].
    pub fn start_with_real_companion() -> Result<(Instance, RealCompanion)> {
        let kit = Kit::find()?;
        let dir = tempfile::tempdir()?;
        let companion = start_real_companion(&kit, dir.path())?;
        let mut instance = Instance::boot_in(kit, dir, Some(&companion))?;
        instance.children.insert(0, companion.child);
        Ok((instance, RealCompanion { socket: companion.socket, web_addr: companion.web_addr }))
    }

    fn boot_in(kit: Kit, dir: TempDir, companion: Option<&StartedCompanion>) -> Result<Instance> {
        crate::kit::refuse_root()?;
        let root = dir.path().to_path_buf();
        let mount = root.join("pvos-system");
        let sockets = root.join("sockets");
        let logs = root.join("logs");
        for d in [&sockets, &logs, &root.join("home")] {
            std::fs::create_dir_all(d)?;
        }
        let env = child_env(&root, &mount);

        let out = Command::new(kit.bin("pvfs"))
            .args(["forest", "init", "--mount"])
            .arg(&mount)
            .envs(env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null())
            .output()?;
        if !out.status.success() {
            return Err(format!("pvfs forest init: {}", String::from_utf8_lossy(&out.stderr)).into());
        }

        let mut children = vec![spawn(
            Command::new(kit.bin("pvfsd")).arg("--mount").arg(&mount).envs(env.iter().map(|(k, v)| (k, v))),
            &logs.join("pvfsd.log"),
        )?];
        let find_socket = || -> Option<PathBuf> {
            std::fs::read_dir(&sockets).ok()?.find_map(|e| {
                let p = e.ok()?.path();
                (p.extension()? == "sock").then_some(p)
            })
        };
        if !wait(Duration::from_secs(20), || find_socket().is_some()) {
            return Err(format!("pvfsd did not come up:\n{}", tail(&logs.join("pvfsd.log"))).into());
        }
        let pvfsd_socket = find_socket().expect("just found");
        let owner_key = DeviceKeyCache::load(&mount.join(".pvfs"))?;

        let control = root.join("control.sock");
        let port = free_port()?;
        let http_addr = format!("127.0.0.1:{port}");
        let mut pvosd = Command::new(kit.bin("pvosd"));
        pvosd
            .arg("--mount")
            .arg(&mount)
            .arg("--pvfsd-socket")
            .arg(&pvfsd_socket)
            .arg("--control-socket")
            .arg(&control)
            .arg("--pvfs-bin")
            .arg(kit.bin("pvfs"))
            .arg("--pvfsd-bin")
            .arg(kit.bin("pvfsd"))
            .arg("--web-dir")
            .arg(kit.web_dir())
            .arg("--http-listen")
            .arg(&http_addr)
            .envs(env.iter().map(|(k, v)| (k, v)));
        if let Some(c) = companion {
            pvosd
                .arg("--companion-socket")
                .arg(&c.socket)
                .env("PVOS_COMPANION_WEB", format!("http://{}", c.web_addr));
        }
        children.push(spawn(&mut pvosd, &logs.join("pvosd.log"))?);

        let up = wait(Duration::from_secs(30), || {
            control.exists() && TcpStream::connect(&http_addr).is_ok()
        });
        let instance = Instance {
            kit,
            dir,
            mount,
            control,
            pvfsd_socket,
            http_addr,
            owner_key,
            owner: None,
            owner_conn: Mutex::new(None),
            children,
        };
        if !up {
            return Err(format!("pvosd did not come up:\n{}", instance.log("pvosd")).into());
        }
        Ok(instance)
    }

    /// Pair someone new with this PVOS (the first is the owner), with throwaway keys
    /// and a companion of their own.
    pub fn add_member(&self, name: &str) -> Result<Member> {
        let new_key = |index| -> Result<Arc<SigningKey>> {
            Ok(Arc::new(identity::device_key(&identity::generate_mnemonic()?, "", index)?))
        };
        let (id_key, enc_key) = (new_key(0)?, new_key(1)?);
        let socket = self.dir.path().join(format!("companion-{name}.sock"));
        crate::companion::spawn(&socket, id_key.clone(), enc_key.clone())?;
        self.owner()?.admin_pair(
            name,
            &format!("dev kit {name}"),
            &socket.display().to_string(),
            vec![self.origin()],
        )?;
        Ok(Member { name: name.into(), identity: id_key, encryption: enc_key, companion_socket: socket })
    }

    /// Pair the kit's real companion as the owner. It asks at the terminal.
    pub fn pair_real_companion(&self, companion: &RealCompanion) -> Result<()> {
        self.owner()?.admin_pair(
            "owner",
            "pvos-dev",
            &companion.socket.display().to_string(),
            vec![self.origin()],
        )?;
        Ok(())
    }

    /// The owner, attached to the control socket. Every `admin_*` call of the SDK
    /// is here, and `call` reaches any app's service.
    pub fn owner(&self) -> Result<Arc<AppConn>> {
        let mut shared = self.owner_conn.lock().expect("the owner's connection");
        if let Some(conn) = shared.as_ref() {
            return Ok(conn.clone());
        }
        let key = &self.owner_key;
        let conn = Arc::new(pvos_sdk::connect(&self.control, &key.pubkey(), |d| {
            crypto::sign_digest(&key.signing_key, d).expect("the owner's key signs")
        })?);
        *shared = Some(conn.clone());
        Ok(conn)
    }

    /// The owner's device key: what signs for the owner on the control socket and
    /// on pvfsd's.
    pub fn owner_key(&self) -> &DeviceKeyCache {
        &self.owner_key
    }

    /// The owner's identity: what signs in to the desktop as the owner.
    pub fn owner_member(&self) -> &Member {
        self.owner.as_ref().expect("this instance pairs its owner at the terminal, not here")
    }

    /// A desktop signed in as the owner.
    pub fn desktop(&self) -> Result<Desktop> {
        self.desktop_as(self.owner_member())
    }

    /// A desktop signed in as `member`.
    pub fn desktop_as(&self, member: &Member) -> Result<Desktop> {
        Desktop::sign_in(&self.http_addr, &member.identity)
    }

    /// Install an app the way `pvos install` does: its own folder, its own new key,
    /// the manifest pointing at the binary there.
    pub fn install(&self, app: &App) -> Result<()> {
        let text = std::fs::read_to_string(&app.manifest)
            .map_err(|e| format!("read {}: {e}", app.manifest.display()))?;
        let mut manifest: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| format!("{}: {e}", app.manifest.display()))?;
        let id = manifest["id"].as_str().ok_or("the manifest has no id")?.to_string();
        let entrypoint = manifest["runtime"]["entrypoint"]
            .as_str()
            .ok_or("the manifest has no runtime.entrypoint")?
            .trim_start_matches("./")
            .to_string();

        let folder = self.app_dir(&id);
        std::fs::create_dir_all(&folder)?;
        let binary = folder.join(&entrypoint);
        std::fs::copy(&app.binary, &binary).map_err(|e| format!("copy {}: {e}", app.binary.display()))?;
        manifest["runtime"]["entrypoint"] = binary.display().to_string().into();
        std::fs::write(folder.join("manifest.json"), manifest.to_string())?;
        let key = DeviceKeyCache {
            signing_key: identity::device_key(&identity::generate_mnemonic()?, "", 0)?,
            device_index: acl::MEMBER_DEVICE_INDEX,
        };
        key.save(&folder)?;
        let ui = match &app.ui {
            Some(ui) => {
                copy_dir(ui, &folder.join("ui"))?;
                let mut files = Vec::new();
                read_ui(ui, "", &mut files)?;
                Some(files)
            }
            None => None,
        };
        self.owner()?.admin_install_app(&id, &hex::encode(key.pubkey()), manifest.to_string(), ui, false)?;
        Ok(())
    }

    /// Run the real `pvos` CLI against this instance, and return what it printed.
    ///
    /// The CLI attaches as the owner, so a connection [`Instance::owner`] gave you
    /// earlier stops working: ask for it again afterwards.
    pub fn pvos(&self, args: &[OsString]) -> Result<String> {
        *self.owner_conn.lock().expect("the owner's connection") = None;
        let mut command = Command::new(self.kit.bin("pvos"));
        command
            .args(args)
            .arg("--daemon")
            .arg(&self.control)
            .arg("--mount")
            .arg(&self.mount)
            .envs(child_env(self.dir.path(), &self.mount).iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null());
        let out = command.output()?;
        if !out.status.success() {
            return Err(format!(
                "pvos {:?}: {}{}",
                args,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
            .into());
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Start an app's process.
    pub fn start_app(&self, id: &str) -> Result<()> {
        Ok(self.owner()?.admin_start_app(id)?)
    }

    /// Stop an app's process.
    pub fn stop_app(&self, id: &str) -> Result<()> {
        Ok(self.owner()?.admin_stop_app(id)?)
    }

    /// The folder an app was installed from: its binary, manifest and `device.key`.
    pub fn app_dir(&self, id: &str) -> PathBuf {
        self.dir.path().join("apps").join(id)
    }

    /// The region an app was given at install: its own storage.
    pub fn app_region(&self, id: &str) -> Result<String> {
        let (apps, _) = self.owner()?.admin_list()?;
        apps.into_iter()
            .find(|a| a.app_id == id)
            .map(|a| a.region)
            .ok_or_else(|| format!("{id} is not installed").into())
    }

    /// Grant an app every method of one of PVOS's own services (`pvos.notify`).
    pub fn grant_service(&self, app: &str, service: &str) -> Result<String> {
        Ok(self.owner()?.admin_grant(
            Subject::App(app.into()),
            Capability {
                kind: CapKind::Service,
                scope: Scope::Service {
                    provider: ProviderId::pvos(),
                    name: service.into(),
                    sel: ServiceSel::All,
                },
            },
            Depth::N(0),
            None,
        )?)
    }

    pub fn kit(&self) -> &Kit {
        &self.kit
    }

    /// The system forest's folder.
    pub fn mount(&self) -> &Path {
        &self.mount
    }

    /// pvosd's control socket.
    pub fn control_socket(&self) -> &Path {
        &self.control
    }

    /// pvfsd's socket.
    pub fn pvfsd_socket(&self) -> &Path {
        &self.pvfsd_socket
    }

    /// The desktop's `host:port`.
    pub fn http_addr(&self) -> &str {
        &self.http_addr
    }

    /// The desktop's address, as a browser's origin.
    pub fn origin(&self) -> String {
        format!("http://{}", self.http_addr)
    }

    /// The last lines a program logged: `pvosd` (which includes every app's), `pvfsd`.
    pub fn log(&self, program: &str) -> String {
        tail(&self.dir.path().join("logs").join(format!("{program}.log")))
    }

    /// The path of a program's log.
    pub fn log_path(&self, program: &str) -> PathBuf {
        self.dir.path().join("logs").join(format!("{program}.log"))
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("--- pvosd's last lines ---\n{}", self.log("pvosd"));
        }
        // pvosd first: apps exit when their session closes. Asked, then told.
        for child in self.children.iter_mut().rev() {
            // SAFETY: kill(2) on a child we still own; a stale pid is impossible
            // before the wait below.
            unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
            let stopped = wait(Duration::from_secs(5), || matches!(child.try_wait(), Ok(Some(_))));
            if !stopped {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

struct StartedCompanion {
    child: Child,
    socket: PathBuf,
    web_addr: String,
}

fn start_real_companion(kit: &Kit, root: &Path) -> Result<StartedCompanion> {
    let home = root.join("companion");
    std::fs::create_dir_all(&home)?;
    let vault = home.join("companion.vault");
    let socket = home.join("companion.sock");
    let port = free_port()?;
    let phrase = identity::generate_mnemonic()?.to_string();
    let bin = kit.bin("pvfs-companion");
    let env = [
        ("PVFS_COMPANION_PASSPHRASE", "throwaway"),
        ("XDG_CONFIG_HOME", home.to_str().ok_or("a temp path that is not text")?),
        ("XDG_RUNTIME_DIR", home.to_str().ok_or("a temp path that is not text")?),
    ];

    let mut init = Command::new(&bin)
        .args(["init", "--passphrase", "--vault"])
        .arg(&vault)
        .envs(env)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    {
        use std::io::Write;
        init.stdin.take().expect("piped").write_all(phrase.as_bytes())?;
    }
    let out = init.wait_with_output()?;
    if !out.status.success() {
        return Err(format!("pvfs-companion init: {}", String::from_utf8_lossy(&out.stderr)).into());
    }

    let mut serve = Command::new(&bin);
    die_with_this_process(&mut serve);
    let child = serve
        .args(["serve", "--prompt", "terminal", "--idle-lock-secs", "0", "--vault"])
        .arg(&vault)
        .arg("--socket")
        .arg(&socket)
        .arg("--web-port")
        .arg(port.to_string())
        .envs(env)
        .stdin(Stdio::null())
        .stdout(File::create(home.join("companion.log"))?)
        .stderr(File::create(home.join("companion.err"))?)
        .spawn()?;
    if !wait(Duration::from_secs(10), || socket.exists()) {
        return Err(format!("the companion did not come up:\n{}", tail(&home.join("companion.err"))).into());
    }
    Ok(StartedCompanion { child, socket, web_addr: format!("127.0.0.1:{port}") })
}

fn child_env(root: &Path, mount: &Path) -> Vec<(&'static str, OsString)> {
    vec![
        ("PVFS_REGISTRY_DIR", root.join("registry").into_os_string()),
        ("PVFS_SOCKET_DIR", root.join("sockets").into_os_string()),
        ("XDG_CONFIG_HOME", root.join("config").into_os_string()),
        ("HOME", root.join("home").into_os_string()),
        ("PVOS_MOUNT", mount.as_os_str().to_os_string()),
        // Not a machine's own install, whatever /etc/default/pvos says, and no
        // share listener on a real address.
        ("PVOS_RELEASE", root.join("no-release").into_os_string()),
        ("PVOS_SHARE_LISTEN", "127.0.0.1:0".into()),
    ]
}

fn spawn(command: &mut Command, log: &Path) -> Result<Child> {
    let out = File::create(log)?;
    die_with_this_process(command);
    Ok(command.stdin(Stdio::null()).stdout(out.try_clone()?).stderr(out).spawn()?)
}

/// A test killed by a timeout, or a `pvos-dev` killed outright, runs no `Drop`: the
/// kernel stops the programs instead, so nothing is left running.
pub(crate) fn die_with_this_process(command: &mut Command) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: prctl is async-signal-safe, and this touches nothing else.
        unsafe {
            command.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = command;
}

pub(crate) fn wait(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    done()
}

fn free_port() -> std::io::Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

fn tail(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(40)..].join("\n")
}

fn read_ui(dir: &Path, prefix: &str, out: &mut Vec<UiFile>) -> std::io::Result<()> {
    let mut items: Vec<_> = std::fs::read_dir(dir)?.collect::<std::io::Result<_>>()?;
    items.sort_by_key(|e| e.file_name());
    for item in items {
        let name = item.file_name().to_string_lossy().into_owned();
        let path = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
        if item.path().is_dir() {
            read_ui(&item.path(), &path, out)?;
        } else {
            out.push(UiFile { path, bytes: std::fs::read(item.path())? });
        }
    }
    Ok(())
}

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let dest = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &dest)?;
        } else {
            std::fs::copy(entry.path(), dest)?;
        }
    }
    Ok(())
}
