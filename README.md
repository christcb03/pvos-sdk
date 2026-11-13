# PVOS SDK

Build apps for [PVOS](#what-pvos-is) without PVOS's source code.

This repository is everything an app builds against, under a license that lets
your app have any license you like. A separate download, the **dev kit**, holds
the real PVOS and PVFS programs, so your app's tests run against the real thing.
You need no account, no token, and no access to anything private.

## Start here

Download the dev kit from this repository's
[releases](https://github.com/christcb03/pvos-sdk/releases), unpack it, and run:

```bash
pvos-devkit/bin/pvos-dev
```

It asks what you want to do. `new` writes a working app, with an end-to-end test
and a GitHub workflow. See [docs/getting-started.md](docs/getting-started.md).

The kit's programs are Linux x86-64. On a Mac or on Windows, use a Linux container
(getting started shows how).

## What's in here

| Crate | What it is |
|---|---|
| `pvos-sdk` | What an app calls. The one dependency most apps need. |
| `pvos-devkit` | The test harness and the `pvos-dev` tool. |
| `pvos-proto` | The manifest, the control socket, the view model, the desktop protocol. |
| `pvfs-client-core` | The PVFS client (`pvos_sdk::pvfs`). |
| `pvfs-crypto` | Keys, signatures and formats (`pvos_sdk::keys`). |
| `pvfs-proto` | PVFS's wire protocol. |
| `pvfs-log` | Log records and the `pv_*` macros. |
| `pvos-app-greeter` | A small worked example. |

Depend on a release by its tag:

```toml
[dependencies]
pvos-sdk = { git = "https://github.com/christcb03/pvos-sdk", tag = "v0.1.2" }

[dev-dependencies]
pvos-devkit = { git = "https://github.com/christcb03/pvos-sdk", tag = "v0.1.2" }
```

## What PVOS is

PVOS is a personal operating system that runs on top of PVFS, an encrypted file
system where every read and write is checked against what its signer was granted.
An app is a process PVOS starts and supervises. It has its own key, its own
storage region, and only the capabilities its owner granted.

## How this repository is made

It is exported from the private PVOS and PVFS repositories, one commit per
release, and it builds and tests alone. Numbers like `D237` in comments name
internal design records.

## License

Everything in this repository is yours to use under either
[MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your choice. Copyright
Turner Networking, LLC. An app built with it can have any license.

The dev kit is a separate download with its own license: PVOS and PVFS are free
for personal use, hobby projects and study, and for schools, charities and
government, under the PolyForm Noncommercial License 1.0.0. In addition, anyone
may use the kit to develop and test software that runs on PVOS, commercial
software included. Running PVOS or PVFS for real at a business needs a commercial
license: licensing@turnernetworking.com.
