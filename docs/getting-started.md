# Getting started

You will have a working app, running in a real PVOS, in a few minutes. You need
Rust 1.96 or newer on Linux x86-64, as a normal user: PVFS won't make a forest as
root. On a Mac or on Windows, do all of this in a Linux container, not as its root:

```bash
docker run -it --platform linux/amd64 --user 1000 -e HOME=/tmp/home -e CARGO_HOME=/tmp/home/cargo \
  -v "$PWD":/work -w /work rust:1.96 bash -c 'mkdir -p $HOME/cargo; exec bash'
```

The app `pvos-dev new` writes comes with a dev container for later.

## 1. Get the dev kit

Download `pvos-devkit-<version>-x86_64-linux.tar.gz` from the
[releases](https://github.com/christcb03/pvos-sdk/releases), and unpack it:

```bash
tar xzf pvos-devkit-*-x86_64-linux.tar.gz
export PATH="$PWD/pvos-devkit/bin:$PATH"
```

## 2. Write an app

```bash
pvos-dev new
```

It asks for the app's name, its id and a folder, and writes a small app that
publishes a service and shows a window, with an end-to-end test, a GitHub workflow
and a dev container.

## 3. Test it

```bash
cd your-app
pvos-dev test
```

The test starts the kit's real `pvosd` and `pvfsd` in a temp folder, installs your
app, and drives it the way a person would: through the owner's control socket and a
signed-in desktop. Nothing is mocked, and nothing is relaxed for testing.

## 4. See it

```bash
pvos-dev run
```

This starts a throwaway PVOS with the real companion, using throwaway keys. It asks
at your terminal before it signs, as it would on a real machine. Open the address it
prints, sign in, and open your app. On a remote machine or in a container, forward
two ports: the desktop's, and the one `/companion.json` on it names.

Press Ctrl-C and it is all gone.

## 5. Write the rest

[Writing an app](16-writing-an-app.md) goes through it piece by piece: the manifest,
attaching, storage, services and events, secrets, logs, and the view-model UI. The
reference docs behind it are here too:

- [The manifest and lifecycle](05-app-manifest-and-lifecycle.md)
- [The control socket](04-control-socket-protocol.md)
- [Services and events](06-service-registry-and-behavior-plane.md)
- [The built-in services](07-built-in-services.md)
- [The desktop and the view model](08-web-desktop-and-view-model.md)

An app is default-deny: it holds its own storage region and nothing else until the
owner grants it more. Ask for what you need in the manifest, and the owner is asked.

## 6. Share it

```bash
pvos-dev package
```

This builds the folder `pvos install` takes. Your app can have any license: this SDK
is `MIT OR Apache-2.0`. Running PVOS itself is free for personal use, hobby projects
and study, and for schools, charities and government; a business needs a commercial
license from Turner Networking, LLC (licensing@turnernetworking.com).

## The test API

```rust
use pvos_devkit::{view, wait_for, App, Instance};

let pvos = Instance::start()?;                     // a forest, pvfsd, pvosd, an owner
pvos.install(&App::new(binary, "manifest.json"))?; // its own folder and key
pvos.grant_service(APP, "pvos.notify")?;           // the owner says yes
pvos.start_app(APP)?;

let owner = pvos.owner()?;                         // every admin_* call of the SDK
let mut desktop = pvos.desktop()?;                 // signed in as the owner
desktop.open_surface(APP, "main");
let window = desktop.next_view(APP, "main");
let rows = view::rows_of_table_with(&window, "name");
```

For an app that reads forests itself, `pvos_devkit::TestForest` serves folders of your
own through the kit's `pvfsd`.
