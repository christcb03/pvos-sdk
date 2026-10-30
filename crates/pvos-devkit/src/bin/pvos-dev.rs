//! `pvos-dev`: write, run, test and package a PVOS app. Run it bare and it asks.

use std::io::{IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{exit, Command};
use std::sync::atomic::{AtomicBool, Ordering};

use pvos_devkit::{App, Instance, Kit};

const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");
const COMMANDS: &[(&str, &str)] = &[
    ("new", "write a working app, with an end-to-end test"),
    ("run", "build this app and run it in a throwaway PVOS"),
    ("test", "cargo test, with the dev kit found"),
    ("package", "build the folder `pvos install` takes"),
];

const USAGE: &str = "\
Usage: pvos-dev [command]

  new [--name <name>] [--id <id>] [--dir <folder>]
                   write a working app, with an end-to-end test
  run              build this app and run it in a throwaway PVOS
  test [args]      cargo test, with the dev kit found
  package          build the folder `pvos install` takes
  version          this tool's version, and the kit's

Run it bare, or a command with nothing else, and it asks for what it needs.
";

// The app `new` writes. {{name}}, {{id}}, {{crate}}, {{sdk}}, {{version}} are filled in.
const TEMPLATE: &[(&str, &str)] = &[
    ("Cargo.toml", include_str!("../../templates/app/Cargo.toml.in")),
    ("manifest.json", include_str!("../../templates/app/manifest.json")),
    ("README.md", include_str!("../../templates/app/README.md")),
    (".gitignore", include_str!("../../templates/app/gitignore")),
    ("src/main.rs", include_str!("../../templates/app/src/main.rs.in")),
    ("tests/end_to_end.rs", include_str!("../../templates/app/tests/end_to_end.rs.in")),
    (".github/workflows/ci.yml", include_str!("../../templates/app/ci.yml")),
    (".devcontainer/devcontainer.json", include_str!("../../templates/app/devcontainer.json")),
];

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match args.first().map(String::as_str) {
        Some("-h" | "--help" | "help") => {
            print!("{USAGE}");
            return;
        }
        Some(c) => c.to_string(),
        None => ask_command(),
    };
    let rest = args.get(1..).unwrap_or_default();
    let result = match command.as_str() {
        "new" => cmd_new(rest),
        "run" => cmd_run(),
        "test" => cmd_test(rest),
        "package" => cmd_package(),
        "version" => cmd_version(),
        other => {
            eprintln!("pvos-dev: no command '{other}'\n\n{USAGE}");
            exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("pvos-dev: {e}");
        exit(1);
    }
}

fn at_terminal() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

fn ask_command() -> String {
    if !at_terminal() {
        eprint!("{USAGE}");
        exit(2);
    }
    println!("What would you like to do?\n");
    for (i, (name, what)) in COMMANDS.iter().enumerate() {
        println!("  {}. {name:8} {what}", i + 1);
    }
    println!();
    let answer = ask("Number or name", Some("new"));
    match answer.parse::<usize>() {
        Ok(n) if (1..=COMMANDS.len()).contains(&n) => COMMANDS[n - 1].0.to_string(),
        _ => answer,
    }
}

/// Ask at the terminal, offering a default. Off a terminal, the default or a
/// usage error naming what is missing.
fn ask(question: &str, default: Option<&str>) -> String {
    if !at_terminal() {
        return match default {
            Some(d) => d.to_string(),
            None => {
                eprintln!("pvos-dev: {question} is needed, and there is no terminal to ask at");
                exit(2);
            }
        };
    }
    loop {
        match default {
            Some(d) => eprint!("{question} [{d}]: "),
            None => eprint!("{question}: "),
        }
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).unwrap_or(0) == 0 {
            exit(2);
        }
        let line = line.trim();
        if !line.is_empty() {
            return line.to_string();
        }
        if let Some(d) = default {
            return d.to_string();
        }
    }
}

fn flag(args: &[String], name: &str) -> Option<String> {
    let at = args.iter().position(|a| a == name)?;
    args.get(at + 1).cloned()
}

fn cmd_new(args: &[String]) -> pvos_devkit::Result<()> {
    let name = flag(args, "--name").unwrap_or_else(|| ask("The app's name", None));
    let slug: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if slug.is_empty() || !slug.as_bytes()[0].is_ascii_lowercase() {
        return Err(format!("'{name}' does not start with a letter, so it can't name a crate").into());
    }
    let id = flag(args, "--id").unwrap_or_else(|| ask("Its id (reverse-DNS)", Some(&format!("com.example.{}", slug.replace('-', "")))));
    let dir = PathBuf::from(flag(args, "--dir").unwrap_or_else(|| ask("Folder to write it in", Some(&slug))));
    if dir.join("Cargo.toml").exists() {
        return Err(format!("{} already holds a Cargo.toml", dir.display()).into());
    }
    // `--sdk-path` builds against an SDK checkout instead of the release tag.
    let source = match flag(args, "--sdk-path") {
        Some(path) => {
            let path = std::fs::canonicalize(&path).map_err(|e| format!("{path}: {e}"))?;
            format!("path = \"{}/crates/@CRATE@\"", path.display())
        }
        None => format!("git = \"https://github.com/christcb03/pvos-sdk\", tag = \"v{SDK_VERSION}\""),
    };
    for (path, text) in TEMPLATE {
        let text = text
            .replace("{{name}}", &name)
            .replace("{{id}}", &id)
            .replace("{{crate}}", &slug)
            .replace("{{crate_snake}}", &slug.replace('-', "_"))
            .replace("{{version}}", SDK_VERSION)
            .replace("{{sdk}}", &source.replace("@CRATE@", "pvos-sdk"))
            .replace("{{devkit}}", &source.replace("@CRATE@", "pvos-devkit"));
        let dest = dir.join(path);
        std::fs::create_dir_all(dest.parent().expect("a template path has a folder"))?;
        std::fs::write(dest, text)?;
    }
    println!("Wrote {name} in {}.\n\n  cd {}\n  pvos-dev run     # see it\n  pvos-dev test    # its end-to-end test", dir.display(), dir.display());
    Ok(())
}

fn cmd_version() -> pvos_devkit::Result<()> {
    println!("pvos-dev {SDK_VERSION}");
    match Kit::find() {
        Ok(kit) => println!(
            "dev kit at {}: PVOS {}, PVFS {}",
            kit.dir().display(),
            kit.version("pvos").unwrap_or_else(|| "?".into()),
            kit.version("pvfs").unwrap_or_else(|| "?".into()),
        ),
        Err(e) => println!("{e}"),
    }
    Ok(())
}

fn cmd_test(args: &[String]) -> pvos_devkit::Result<()> {
    let kit = Kit::find()?;
    let status = Command::new("cargo").arg("test").args(args).env("PVOS_DEVKIT", kit.dir()).status()?;
    exit(status.code().unwrap_or(1));
}

/// This folder's manifest, and the binary its entrypoint names.
fn this_app() -> pvos_devkit::Result<(serde_json::Value, String)> {
    let path = Path::new("manifest.json");
    let text = std::fs::read_to_string(path).map_err(|_| "there is no manifest.json here: run this in your app's folder")?;
    let manifest: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("manifest.json: {e}"))?;
    let binary = manifest["runtime"]["entrypoint"]
        .as_str()
        .ok_or("manifest.json has no runtime.entrypoint")?
        .trim_start_matches("./")
        .to_string();
    Ok((manifest, binary))
}

fn cargo_build(release: bool, binary: &str) -> pvos_devkit::Result<PathBuf> {
    let mut cargo = Command::new("cargo");
    cargo.args(["build", "--bin", binary]);
    if release {
        cargo.arg("--release");
    }
    if !cargo.status()?.success() {
        return Err("the build failed".into());
    }
    let target = std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from).unwrap_or_else(|| "target".into());
    Ok(target.join(if release { "release" } else { "debug" }).join(binary))
}

fn cmd_package() -> pvos_devkit::Result<()> {
    let (_, binary) = this_app()?;
    let built = cargo_build(true, &binary)?;
    let folder = Path::new("dist").join(&binary);
    std::fs::create_dir_all(&folder)?;
    std::fs::copy("manifest.json", folder.join("manifest.json"))?;
    std::fs::copy(&built, folder.join(&binary))?;
    if Path::new("ui").is_dir() {
        let status = Command::new("cp").args(["-R", "ui"]).arg(&folder).status()?;
        if !status.success() {
            return Err("copying ui/ failed".into());
        }
    }
    println!(
        "Packaged {}.\n\nOn a server running PVOS, copy that folder over and run:\n\n  pvos install {binary}\n\n\
         This binary needs the same libc as the machine that built it. To run anywhere, build for\n\
         x86_64-unknown-linux-musl.",
        folder.display()
    );
    Ok(())
}

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_interrupt(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

fn cmd_run() -> pvos_devkit::Result<()> {
    let (manifest, binary) = this_app()?;
    let id = manifest["id"].as_str().ok_or("manifest.json has no id")?.to_string();
    let built = cargo_build(false, &binary)?;

    println!("Starting a throwaway PVOS. It is gone when you stop this.\n");
    let (pvos, companion) = Instance::start_with_real_companion()?;
    println!(
        "The companion is the real one, with throwaway keys, and it asks here before it signs.\n\
         Say yes to pairing it now, and to signing in when your browser asks.\n"
    );
    pvos.pair_real_companion(&companion)?;
    pvos.install(&App::new(&built, "manifest.json"))?;

    // What the app asks for at its first start, granted now: there is no owner at a
    // desktop yet to approve it. A service grant is all this can do for you.
    if let Some(required) = manifest["capabilities"]["required"].as_array() {
        for capability in required {
            if capability["kind"].as_str() == Some("service") {
                if let Some(service) = capability["scope_hint"].as_str() {
                    match pvos.grant_service(&id, service) {
                        Ok(_) => println!("Granted {service}."),
                        Err(e) => println!("Could not grant {service}: {e}"),
                    }
                }
            }
        }
    }
    pvos.start_app(&id)?;
    println!("\nOpen {}/ in a browser. Press Ctrl-C to stop.\n", pvos.origin());

    // SAFETY: the handler only stores to an atomic.
    unsafe {
        libc::signal(libc::SIGINT, on_interrupt as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_interrupt as *const () as libc::sighandler_t);
    }
    // PVOS logs every app's lines too, so this is the app's output and PVOS's.
    let mut log = std::fs::File::open(pvos.log_path("pvosd"))?;
    let mut at = 0;
    while !STOP.load(Ordering::SeqCst) {
        log.seek(SeekFrom::Start(at))?;
        let mut new = String::new();
        at += log.read_to_string(&mut new)? as u64;
        print!("{new}");
        let _ = std::io::stdout().flush();
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    println!("\nStopping.");
    Ok(())
}
