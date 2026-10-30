//! `pvos-app-greeter` — the M2 example app, run under `pvosd` supervision.
//!
//! Launched with `PVOS_CONTROL_SOCKET` (Channel 2) and `PVOS_APP_DIR` (where
//! `pvos install` put its `device.key`). It publishes `greeter@1.0.0`
//! (`greet`, plus the async `greet_slowly` — doc 06 §6.1), emits an event on
//! `greetings` for every greet, and — capability-driven — registers a
//! recurring scheduler job calling its own `greet` if (and only if) the
//! owner granted it `schedule`. Behavior follows authority: grant the
//! capability and the demo job appears; don't, and it can't even ask.
//!
//! M3: it also renders a Mode B surface, `main` — a table of received
//! greetings, a greet form, and a streaming `log` fed by `AppendLog` on
//! every greet (doc 08 §4). Push/UiEvent/AppendLog all exercised.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pvos_sdk::keys::{crypto, identity::DeviceKeyCache};
use pvos_proto::{
    AlertLevel, CallOutcome, CapKind, Component, Job, Schedule, Scope, ServiceCallSpec, UiPhase,
    ViewModel,
};
use pvos_sdk::{content, meta, pv_error, pv_info, pv_notice};
use serde_json::json;

/// Build the `main` surface view-model from the greeting history.
fn main_view(greeted: &[String]) -> ViewModel {
    let rows: Vec<Vec<String>> = greeted
        .iter()
        .rev()
        .take(10)
        .map(|n| vec![n.clone(), format!("hello {n}")])
        .collect();
    ViewModel {
        back: None,
        root: Component::Stack {
            id: None,
            horizontal: false,
            children: vec![
                Component::Heading {
                    text: "Greeter".into(),
                },
                if rows.is_empty() {
                    Component::Alert {
                        level: AlertLevel::Info,
                        text: "No greetings yet — say hello.".into(),
                    }
                } else {
                    Component::Table {
                        columns: vec!["name".into(), "reply".into()],
                        rows,
                        row_action: None,
                        row_buttons: vec![],
                        row_keys: vec![],
                        time_columns: vec![],
                    }
                },
                Component::Form {
                    action: "greet".into(),
                    children: vec![Component::Field {
                        id: Some("name".into()),
                        label: "Name".into(),
                        value: String::new(),
                        action: None,
                        secret: false,
                    }],
                    horizontal: false,
                },
                Component::Log {
                    id: "activity".into(),
                    lines: vec![],
                },
            ],
        },
    }
}

fn main() {
    pvos_sdk::init_logging("greeter");
    let control = std::env::var("PVOS_CONTROL_SOCKET").expect("PVOS_CONTROL_SOCKET");
    let app_dir = std::env::var("PVOS_APP_DIR").expect("PVOS_APP_DIR");
    let key = DeviceKeyCache::load(Path::new(&app_dir)).expect("device.key in PVOS_APP_DIR");
    let pubkey = key.pubkey();

    let conn = Arc::new(
        pvos_sdk::connect(Path::new(&control), &pubkey, |d| {
            crypto::sign_digest(&key.signing_key, d).unwrap()
        })
        .expect("attach"),
    );
    let app_id = conn.context().app_id.clone();
    pv_notice!("pvos.greeter.attached", app = &app_id; "{app_id}: attached");

    // Greeting history shared by the service handler and the UI surface.
    let greeted: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    // One place records a greet: history + event + surface log + re-push.
    let record_greet = {
        let conn = conn.clone();
        let greeted = greeted.clone();
        move |name: &str| {
            greeted.lock().unwrap().push(name.to_string());
            let _ = conn.emit("greetings", json!({ "name": name }));
            let _ = conn.append_log("main", "activity", vec![format!("greeted {name}")]);
            let _ = conn.push_view_model("main", main_view(&greeted.lock().unwrap()));
        }
    };

    // Handler before publish, so no call finds us handler-less.
    let handler_conn = conn.clone();
    let handler_record = record_greet.clone();
    conn.on_call(move |_service, method, args| match method {
        "greet" => {
            let name = args
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();
            handler_record(&name);
            CallOutcome::Ok {
                value: json!(format!("hello {name}")),
            }
        }
        "greet_slowly" => {
            // Async-job pattern (doc 06 §6.1 / D17): return a handle now,
            // progress + completion as events on job/<id>.
            let job_id = format!(
                "slow-{:x}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            );
            let topic = format!("{}{job_id}", pvos_proto::JOB_TOPIC_PREFIX);
            let emitter = handler_conn.clone();
            std::thread::spawn(move || {
                for step in 1..=3 {
                    std::thread::sleep(Duration::from_millis(150));
                    let _ = emitter.emit(&topic, json!({ "progress": step * 33 }));
                }
                let _ = emitter.emit(&topic, json!({ "done": true, "result": "hello slowly" }));
            });
            CallOutcome::Ok {
                value: json!({ "job_id": job_id }),
            }
        }
        other => CallOutcome::Err {
            code: "no_such_method".into(),
            message: format!("greeter has no method '{other}'"),
        },
    });

    conn.publish(pvos_proto::manifest::ServiceDecl {
        name: "greeter".into(),
        version: "1.0.0".into(),
        interface: None,
        methods: vec!["greet".into(), "greet_slowly".into()],
        api: vec![pvos_proto::manifest::ApiMethod {
            name: "greet".into(),
            companion: false,
        }],
    })
    .expect("publish");

    // ── the Mode B surface (M3, doc 08 §4) ──────────────────────────────
    // Window opened/focused → (re-)push the current view.
    {
        let conn2 = conn.clone();
        let greeted2 = greeted.clone();
        conn.on_lifecycle(move |surface, phase, _actor| {
            if surface == "main" && matches!(phase, UiPhase::Open | UiPhase::Focus) {
                let _ = conn2.push_view_model("main", main_view(&greeted2.lock().unwrap()));
            }
        });
    }
    // The greet form submits → same path as a service-call greet.
    {
        let ui_record = record_greet.clone();
        conn.on_ui_event(move |surface, action, payload, _actor| {
            if surface == "main" && action == "greet" {
                let name = payload
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string();
                ui_record(&name);
            }
        });
    }

    // Capability-driven demo job: if the owner granted `schedule`, keep a
    // recurring self-call registered (doc 07 §2's "call my own service X").
    let has_schedule = conn
        .list_capabilities()
        .unwrap_or_default()
        .iter()
        .any(|c| {
            c.kind == CapKind::Service
                && matches!(&c.scope, Scope::Service { provider, name, .. }
                    if provider.0 == "pvos" && name == "pvos.scheduler")
        });
    if has_schedule {
        let sched = pvos_proto::ProviderId::pvos();
        // Idempotent across restarts: the job store is persistent, so only
        // register if we don't already have one.
        let existing = conn
            .call(&sched, "pvos.scheduler", "list", json!({}))
            .ok()
            .and_then(|v| v.as_array().map(|a| !a.is_empty()))
            .unwrap_or(false);
        if existing {
            pv_info!("pvos.greeter.demo_job_present", app = &app_id; "{app_id}: demo job already registered");
        } else {
        let job = Job {
            id: None,
            schedule: Schedule::Every { interval_ms: 500, first_at_ms: None },
            action: ServiceCallSpec {
                provider: pvos_proto::ProviderId(app_id.clone()),
                service: "greeter".into(),
                method: "greet".into(),
                args: json!({ "name": "auto" }),
            },
        };
        match conn.call(
            &sched,
            "pvos.scheduler",
            "register",
            serde_json::to_value(&job).unwrap(),
        ) {
            Ok(v) => pv_notice!("pvos.greeter.demo_job_registered", app = &app_id, job = meta(&v);
                "{app_id}: registered demo job {v}"),
            Err(e) => pv_error!("pvos.greeter.demo_job_failed", app = &app_id, error = content(&e);
                "{app_id}: demo job not registered: {e}"),
        }
        }
    }

    pv_notice!("pvos.greeter.serving", app = &app_id; "{app_id}: serving");
    conn.wait_closed();
    pv_notice!("pvos.greeter.exiting", app = &app_id; "{app_id}: session closed — exiting");
}
