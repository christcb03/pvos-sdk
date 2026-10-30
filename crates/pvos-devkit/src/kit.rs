use std::path::{Path, PathBuf};

use crate::Result;

/// The dev kit: the real PVOS and PVFS programs, a separate download.
#[derive(Clone, Debug)]
pub struct Kit {
    dir: PathBuf,
}

/// PVFS won't make a forest as root (its files would be root's for good), so nothing
/// here can run as root: say so before it fails further in.
pub(crate) fn refuse_root() -> Result<()> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    root_refusal(unsafe { libc::geteuid() }).map_or(Ok(()), |why| Err(why.into()))
}

fn root_refusal(euid: u32) -> Option<&'static str> {
    (euid == 0).then_some(
        "This is running as root, and PVFS won't make a forest as root. Run it as a normal \
         user. In a container: docker run --user 1000 -e HOME=/tmp/home -e CARGO_HOME=/tmp/home/cargo … \
         (see docs/getting-started.md).",
    )
}

const GET_IT: &str = "Download a dev kit from https://github.com/christcb03/pvos-sdk/releases, \
unpack it, and set PVOS_DEVKIT to its folder, or run your tests with `pvos-dev test`.";

impl Kit {
    /// `$PVOS_DEVKIT`, else `~/.pvos/devkit/current`, else the kit this program
    /// itself came from (`pvos-dev` sits in the kit's `bin/`).
    pub fn find() -> Result<Kit> {
        if let Some(dir) = std::env::var_os("PVOS_DEVKIT").filter(|d| !d.is_empty()) {
            let kit = Kit::at(Path::new(&dir));
            return kit.map_err(|e| format!("PVOS_DEVKIT: {e} {GET_IT}").into());
        }
        if let Some(home) = std::env::var_os("HOME") {
            if let Ok(kit) = Kit::at(&Path::new(&home).join(".pvos/devkit/current")) {
                return Ok(kit);
            }
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent().and_then(Path::parent) {
                if let Ok(kit) = Kit::at(dir) {
                    return Ok(kit);
                }
            }
        }
        Err(format!("No PVOS dev kit found. {GET_IT}").into())
    }

    /// The kit at `dir`, if that is one and it speaks this SDK's API.
    pub fn at(dir: &Path) -> Result<Kit> {
        let kit = Kit { dir: dir.to_path_buf() };
        for name in ["pvosd", "pvfsd", "pvfs", "pvos"] {
            if !kit.bin(name).is_file() {
                return Err(format!("{} is not a dev kit: it has no bin/{name}.", dir.display()).into());
            }
        }
        if let Some(api) = kit.version("api_version") {
            let ours = pvos_sdk::proto::API_VERSION.to_string();
            if api != ours {
                return Err(format!(
                    "{} speaks PVOS API {api}, and this SDK speaks {ours}. Use the kit released with this SDK.",
                    dir.display()
                )
                .into());
            }
        }
        Ok(kit)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// A program in the kit.
    pub fn bin(&self, name: &str) -> PathBuf {
        self.dir.join("bin").join(name)
    }

    /// The built desktop.
    pub fn web_dir(&self) -> PathBuf {
        self.dir.join("web")
    }

    /// One line of the kit's `VERSION` file (`sdk`, `pvos`, `pvfs`, `api_version`).
    pub fn version(&self, key: &str) -> Option<String> {
        let text = std::fs::read_to_string(self.dir.join("VERSION")).ok()?;
        text.lines().find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == key).then(|| v.trim().to_string())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::root_refusal;

    #[test]
    fn root_is_told_why_and_what_to_do() {
        assert!(root_refusal(1000).is_none());
        let why = root_refusal(0).unwrap();
        assert!(why.contains("won't make a forest as root") && why.contains("--user 1000"), "{why}");
    }
}
