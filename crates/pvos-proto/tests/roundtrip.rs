//! Serde round-trips for every wire type (M1 build-checklist §1), plus
//! fixture tests pinning the JSON shapes from docs 02 §2, 04 §3, and 05 §1.

use pvos_proto::*;
use serde_json::json;

fn roundtrip<T>(v: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let s = serde_json::to_string(v).unwrap();
    let back: T = serde_json::from_str(&s).unwrap();
    assert_eq!(&back, v, "round-trip changed value; wire was: {s}");
    back
}

fn storage_cap() -> Capability {
    Capability::storage("abc123", Rights(Rights::R | Rights::W))
}

// ── capability ──────────────────────────────────────────────────────────────

#[test]
fn rights_encoding() {
    assert_eq!(serde_json::to_value(Rights(1)).unwrap(), json!("r"));
    assert_eq!(serde_json::to_value(Rights(3)).unwrap(), json!("rw"));
    assert_eq!(serde_json::to_value(Rights(7)).unwrap(), json!("rwa"));
    let r: Rights = serde_json::from_value(json!("rw")).unwrap();
    assert!(r.read() && r.write() && !r.admin());
    assert!(serde_json::from_value::<Rights>(json!("x")).is_err());
    assert!(Rights(1).subset_of(Rights(3)));
    assert!(!Rights(4).subset_of(Rights(3)));
}

#[test]
fn capability_roundtrips_and_wire_shape() {
    let cap = roundtrip(&storage_cap());
    // Pin the doc 02 §2 shape: kind lowercase, storage scope uses "node".
    let v = serde_json::to_value(&cap).unwrap();
    assert_eq!(v, json!({"kind":"storage","scope":{"node":"abc123","rights":"rw"}}));

    roundtrip(&Capability {
        kind: CapKind::Service,
        scope: Scope::Service {
            provider: ProviderId::pvos(),
            name: "pvos.keychain".into(),
            sel: ServiceSel::Entries(vec!["db-pw".into()]),
        },
    });
    roundtrip(&Capability {
        kind: CapKind::Publish,
        scope: Scope::Publish { names: vec!["greeter".into()] },
    });
    roundtrip(&Capability {
        kind: CapKind::Ui,
        scope: Scope::Ui { surfaces: vec!["main".into()] },
    });
    roundtrip(&Capability { kind: CapKind::Federation, scope: Scope::Federation {} });
    roundtrip(&Capability {
        kind: CapKind::Exec,
        scope: Scope::Exec { programs: vec!["/usr/bin/true".into()] },
    });
    roundtrip(&Capability {
        kind: CapKind::Net,
        scope: Scope::Net { hosts: vec!["example.com".into()] },
    });
}

#[test]
fn service_sel_shapes() {
    assert_eq!(serde_json::to_value(ServiceSel::All).unwrap(), json!("all"));
    assert_eq!(
        serde_json::to_value(ServiceSel::Methods(vec!["greet".into()])).unwrap(),
        json!({"methods":["greet"]})
    );
}

#[test]
fn scope_untagged_discrimination() {
    // Empty object must land on Federation (kept last) and nothing else.
    let cap: Capability =
        serde_json::from_value(json!({"kind":"federation","scope":{}})).unwrap();
    assert!(matches!(cap.scope, Scope::Federation {}));
    cap.validate().unwrap();

    // kind/scope mismatch is caught by validate(), not serde.
    let bad: Capability =
        serde_json::from_value(json!({"kind":"exec","scope":{"node":"x","rights":"r"}}))
            .unwrap();
    assert!(bad.validate().is_err());
    storage_cap().validate().unwrap();
}

// ── grants ──────────────────────────────────────────────────────────────────

#[test]
fn grant_record_roundtrips() {
    let grant = Grant {
        id: GrantId("g-1".into()),
        subject: Subject::App("hello".into()),
        capability: storage_cap(),
        issuer: Issuer::Owner,
        redelegation_depth: Depth::N(0),
        expiry: None,
        issued_at: 1_780_000_000_000,
    };
    roundtrip(&GrantRecord::Grant(grant.clone()));
    roundtrip(&GrantRecord::Revoke { grant: GrantId("g-1".into()), at: 1_780_000_000_001 });
    roundtrip(&grant);
}

#[test]
fn grant_wire_shape_matches_doc02() {
    // The doc 02 §2 fixture (timestamps as ms; author/sig live in the PVFS event).
    let v = json!({
        "type": "grant",
        "id": "g-mf-1",
        "subject": "app:mediaforest",
        "capability": {
            "kind": "storage",
            "scope": { "node": "1f2e3d", "rights": "r" }
        },
        "issuer": "app:iac",
        "redelegation_depth": 0,
        "issued_at": 1_766_000_000_000u64
    });
    let rec: GrantRecord = serde_json::from_value(v).unwrap();
    let GrantRecord::Grant(g) = &rec else { panic!("expected grant") };
    assert_eq!(g.subject, Subject::App("mediaforest".into()));
    assert_eq!(g.issuer, Issuer::App("iac".into()));
    assert_eq!(g.redelegation_depth, Depth::N(0));
    assert_eq!(g.expiry, None);
    roundtrip(&rec);
}

#[test]
fn depth_and_principal_encodings() {
    assert_eq!(serde_json::to_value(Depth::N(2)).unwrap(), json!(2));
    assert_eq!(serde_json::to_value(Depth::Unlimited).unwrap(), json!("unlimited"));
    assert!(serde_json::from_value::<Depth>(json!("lots")).is_err());

    assert_eq!(serde_json::to_value(Subject::Key("aa11".into())).unwrap(), json!("key:aa11"));
    assert!(serde_json::from_value::<Subject>(json!("hello")).is_err());
    assert_eq!(serde_json::to_value(Issuer::Owner).unwrap(), json!("owner"));
    assert!(serde_json::from_value::<Issuer>(json!("root")).is_err());
}

// ── manifest ────────────────────────────────────────────────────────────────

#[test]
fn manifest_roundtrips_and_parses_doc05_shape() {
    let v = json!({
        "id": "com.example.hello",
        "version": "1.2.0",
        "api_version": 1,
        "display_name": "Hello",
        "publisher": "key:aa11",
        "tier": "user",
        "residency": "integrated",
        "capabilities": {
            "required": [
                { "kind": "storage", "scope_hint": "own-region", "reason": "store its data" }
            ],
            "optional": [
                { "kind": "service", "scope_hint": ["db-pw"], "reason": "DB access" }
            ]
        },
        "node_types": ["hello.note"],
        "services_provided": [
            { "name": "greeter", "version": "1.0.0", "methods": ["greet"] }
        ],
        "services_consumed": [
            { "name": "pvos.keychain", "version": "^1", "optional": false }
        ],
        "ui": { "surfaces": [ { "name": "main", "mode": "iframe", "entry": "served" } ] },
        "headless": false,
        "runtime": { "kind": "native", "entrypoint": "./hello" },
        "integrity": { "sig": "deadbeef" }
    });
    let m: AppManifest = serde_json::from_value(v).unwrap();
    assert_eq!(m.tier, Tier::User);
    assert_eq!(m.residency, Residency::Integrated);
    assert_eq!(m.capabilities.required.len(), 1);
    assert!(matches!(m.capabilities.required[0].scope_hint, ScopeHint::Named(_)));
    assert!(matches!(m.capabilities.optional[0].scope_hint, ScopeHint::List(_)));
    roundtrip(&m);

    // integrity carries the optional ui_root (M3.7); both fields round-trip.
    let mi: AppManifest = serde_json::from_value(json!({
        "id": "a", "version": "1", "api_version": 1, "display_name": "A",
        "tier": "user", "residency": "integrated",
        "runtime": { "kind": "native", "entrypoint": "./run" },
        "integrity": { "sig": "aa", "ui_root": "beef" }
    }))
    .unwrap();
    let integ = mi.integrity.as_ref().unwrap();
    assert_eq!(integ.sig.as_deref(), Some("aa"));
    assert_eq!(integ.ui_root.as_deref(), Some("beef"));
    roundtrip(&mi);

    // Isolated residency shape.
    let r: Residency = serde_json::from_value(json!({"isolated":{"forest":"f1"}})).unwrap();
    assert_eq!(r, Residency::Isolated { forest: "f1".into() });
    roundtrip(&r);
}

#[test]
fn minimal_headless_manifest() {
    // What `hello` will actually ship in M1: the minimum viable manifest.
    let v = json!({
        "id": "hello",
        "version": "0.1.0",
        "api_version": 1,
        "display_name": "Hello",
        "tier": "user",
        "residency": "integrated",
        "capabilities": { "required": [ { "kind": "storage", "scope_hint": "own-region" } ] },
        "headless": true,
        "runtime": { "kind": "native", "entrypoint": "./hello" }
    });
    let m: AppManifest = serde_json::from_value(v).unwrap();
    assert!(m.headless && m.services_provided.is_empty() && m.ui.surfaces.is_empty());
    roundtrip(&m);
}

// ── control socket ──────────────────────────────────────────────────────────

fn ctx() -> Context {
    Context {
        app_id: "hello".into(),
        region_root: "abc123".into(),
        grants_root: Some("def456".into()),
        pvfsd_socket: "/run/pvfsd.sock".into(),
        capabilities: vec![storage_cap()],
        api_version: API_VERSION,
        pvosd_build: None,
    }
}

/// PVOS D205: the owner's context carries the daemon's build; an older
/// daemon's context (no such field) still decodes, with none.
#[test]
fn context_build_is_optional_on_the_wire() {
    let mut c = ctx();
    c.pvosd_build = Some("0f55c65-dirty".into());
    roundtrip(&ServerMsg::Ready { context: c.clone() });
    let v = serde_json::to_value(&c).unwrap();
    assert_eq!(v["pvosd_build"], "0f55c65-dirty");
    let old = json!({
        "app_id": "@owner", "region_root": "r", "pvfsd_socket": "/s",
        "capabilities": [], "api_version": 1
    });
    let decoded: Context = serde_json::from_value(old).unwrap();
    assert_eq!(decoded.pvosd_build, None);
    assert!(serde_json::to_value(ctx()).unwrap().get("pvosd_build").is_none(), "omitted when absent");
}

#[test]
fn control_messages_roundtrip() {
    roundtrip(&ServerMsg::Challenge {
        nonce: "00ff".into(),
        instance_id: "inst-1".into(),
        expiry_ms: 5000,
    });
    roundtrip(&ClientMsg::Auth { pubkey: "aa11".into(), sig: "bb22".into() });
    roundtrip(&ServerMsg::Ready { context: ctx() });
    roundtrip(&ClientMsg::GetContext { req_id: 7 });
    roundtrip(&ServerMsg::Context { req_id: 7, context: ctx() });
    roundtrip(&ServerMsg::Error {
        req_id: None,
        code: "unauthorized".into(),
        message: "key not a registered app".into(),
    });

    // Tag shape is "type" (doc 04 taxonomy).
    let v = serde_json::to_value(ClientMsg::GetContext { req_id: 1 }).unwrap();
    assert_eq!(v, json!({"type":"get_context","req_id":1}));
}

// ── framing ─────────────────────────────────────────────────────────────────

#[test]
fn frame_roundtrip_and_eof() {
    let mut buf = Vec::new();
    frame::write_frame(&mut buf, &ClientMsg::GetContext { req_id: 42 }).unwrap();
    // u32 LE length prefix
    let len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
    assert_eq!(len, buf.len() - 4);

    let mut r = std::io::Cursor::new(buf);
    let msg: ClientMsg = frame::read_frame(&mut r).unwrap().unwrap();
    assert_eq!(msg, ClientMsg::GetContext { req_id: 42 });
    // Clean EOF → Ok(None)
    assert!(frame::read_frame::<_, ClientMsg>(&mut r).unwrap().is_none());
}

#[test]
fn frame_rejects_oversize() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(frame::MAX_FRAME + 1).to_le_bytes());
    buf.extend_from_slice(b"{}");
    let mut r = std::io::Cursor::new(buf);
    assert!(frame::read_frame::<_, ClientMsg>(&mut r).is_err());
}

// ── M2: behavior plane (doc 04 §4.2–4.3, doc 06, doc 07 §2) ─────────────────

#[test]
fn m2_capability_messages_roundtrip() {
    roundtrip(&ClientMsg::ListCapabilities { req_id: 1 });
    roundtrip(&ClientMsg::ValidateDelegation {
        req_id: 2,
        capability: storage_cap(),
        depth: Depth::N(0),
    });
    roundtrip(&ClientMsg::NotifyGrantsChanged { req_id: 3 });
    roundtrip(&ServerMsg::Ack { req_id: 3 });
    roundtrip(&ServerMsg::Capabilities { req_id: 1, capabilities: vec![storage_cap()] });
    roundtrip(&ServerMsg::CapabilityChanged {
        change: CapChange::Revoked,
        capability: storage_cap(),
    });
    assert_eq!(
        serde_json::to_value(CapChange::Granted).unwrap(),
        json!("granted")
    );
}

#[test]
fn m2_service_messages_roundtrip() {
    let decl = ServiceDecl {
        name: "greeter".into(),
        version: "1.0.0".into(),
        interface: Some("pvfs://schema".into()),
        methods: vec!["greet".into()],
        api: vec![pvos_proto::manifest::ApiMethod {
            name: "greet".into(),
            companion: false,
        }],
    };
    roundtrip(&ClientMsg::PublishService { req_id: 1, decl });
    roundtrip(&ClientMsg::UnpublishService { req_id: 2, name: "greeter".into() });
    roundtrip(&ClientMsg::DiscoverServices { req_id: 3, query: None });
    roundtrip(&ClientMsg::CallService {
        req_id: 4,
        provider: ProviderId::pvos(),
        service: "pvos.scheduler".into(),
        method: "register".into(),
        args: json!({"x": 1}),
        version: None,
    });
    roundtrip(&ClientMsg::ServiceReply {
        call_id: 9,
        outcome: CallOutcome::Ok { value: json!("hi") },
    });
    roundtrip(&ClientMsg::Subscribe { req_id: 5, topic: "greetings".into(), provider: None });
    roundtrip(&ClientMsg::Subscribe { req_id: 6, topic: "greetings".into(), provider: Some(ProviderId("greeter".into())) });
    // PVOS D254: an old app's subscribe (no provider) still decodes — as its own topics.
    let old: ClientMsg = serde_json::from_str(r#"{"type":"subscribe","req_id":7,"topic":"greetings"}"#).unwrap();
    assert_eq!(old, ClientMsg::Subscribe { req_id: 7, topic: "greetings".into(), provider: None });
    roundtrip(&ClientMsg::EmitEvent { req_id: 6, topic: "greetings".into(), payload: json!(1) });

    roundtrip(&ServerMsg::Services {
        req_id: 3,
        services: vec![ServiceInfo {
            name: "greeter".into(),
            provider: ProviderId("key:aa".into()),
            versions: vec!["1.0.0".into()],
            interface_ref: None,
        }],
    });
    roundtrip(&ServerMsg::CallResult {
        req_id: 4,
        outcome: CallOutcome::Err { code: "denied".into(), message: "no capability".into() },
    });
    roundtrip(&ServerMsg::IncomingServiceCall {
        call_id: 9,
        from: "caller".into(),
        service: "greeter".into(),
        method: "greet".into(),
        args: json!({"name": "sam"}),
    });
    roundtrip(&ServerMsg::ServiceEvent { topic: "job/j1".into(), payload: json!({"done": true}), provider: Some(ProviderId("greeter".into())) });
}

#[test]
fn m2_scheduler_job_shapes() {
    let job = Job {
        id: None,
        schedule: Schedule::Every { interval_ms: 60_000, first_at_ms: None },
        action: ServiceCallSpec {
            provider: ProviderId("key:aa".into()),
            service: "housekeeping".into(),
            method: "run".into(),
            args: json!({}),
        },
    };
    roundtrip(&job);
    // Wire shape pins.
    assert_eq!(
        serde_json::to_value(Schedule::OneShot { at_ms: 5 }).unwrap(),
        json!({"kind":"one_shot","at_ms":5})
    );
    let v = serde_json::to_value(&job).unwrap();
    assert!(v.get("id").is_none(), "unassigned id stays off the wire");
}

// PVOS D259 — member actions: the manifest field, its checks, the op.
#[test]
fn d259_member_actions_in_the_manifest_and_on_the_wire() {
    use pvos_proto::manifest::{check_member_actions, MemberAction};
    let m: AppManifest = serde_json::from_value(json!({
        "id": "com.example.mon", "version": "1.0.0", "api_version": 1, "display_name": "Mon",
        "tier": "system", "residency": "integrated", "runtime": {"kind": "native", "entrypoint": "./mon"},
        "member_actions": [{"name": "acknowledge", "description": "Acknowledge a signature"}],
    }))
    .unwrap();
    assert_eq!(m.member_actions.len(), 1);
    roundtrip(&m);
    let old: AppManifest = serde_json::from_value(json!({
        "id": "com.example.old", "version": "1.0.0", "api_version": 1, "display_name": "Old",
        "tier": "system", "residency": "integrated", "runtime": {"kind": "native", "entrypoint": "./old"},
    }))
    .unwrap();
    assert!(old.member_actions.is_empty(), "a manifest from before D259 declares none");
    let a = |n: &str| MemberAction { name: n.into(), description: "does a thing".into() };
    assert!(check_member_actions(&[a("acknowledge"), a("map.edit"), a("run-2")]).is_ok());
    for bad in ["", "Ack", "1st", "with space", &"x".repeat(33)] {
        assert!(check_member_actions(&[a(bad)]).is_err(), "{bad:?} must be refused");
    }
    assert!(check_member_actions(&[a("ack"), a("ack")]).unwrap_err().contains("twice"));
    assert!(check_member_actions(&(0..33).map(|i| a(&format!("a{i}"))).collect::<Vec<_>>()).is_err());
    assert!(check_member_actions(&[MemberAction { name: "ack".into(), description: " ".into() }]).is_err());
    roundtrip(&pvos_proto::desktop::SettingsOp::MemberSetAppActions {
        member: "kim".into(),
        app_id: "com.example.mon".into(),
        actions: vec!["acknowledge".into()],
    });
}

#[test]
fn m2_mixed_stream_decodes_in_order() {
    // A realistic session slice: response, push, response — one buffer.
    let mut buf = Vec::new();
    frame::write_frame(&mut buf, &ServerMsg::Ack { req_id: 1 }).unwrap();
    frame::write_frame(
        &mut buf,
        &ServerMsg::ServiceEvent { topic: "t".into(), payload: json!(1), provider: None },
    )
    .unwrap();
    frame::write_frame(
        &mut buf,
        &ServerMsg::CallResult { req_id: 2, outcome: CallOutcome::Ok { value: json!(null) } },
    )
    .unwrap();
    let mut r = std::io::Cursor::new(buf);
    assert!(matches!(
        frame::read_frame::<_, ServerMsg>(&mut r).unwrap().unwrap(),
        ServerMsg::Ack { req_id: 1 }
    ));
    assert!(matches!(
        frame::read_frame::<_, ServerMsg>(&mut r).unwrap().unwrap(),
        ServerMsg::ServiceEvent { .. }
    ));
    assert!(matches!(
        frame::read_frame::<_, ServerMsg>(&mut r).unwrap().unwrap(),
        ServerMsg::CallResult { req_id: 2, .. }
    ));
    assert!(frame::read_frame::<_, ServerMsg>(&mut r).unwrap().is_none());
}

#[test]
fn m2_admin_messages_roundtrip() {
    roundtrip(&ClientMsg::AdminInstall {
        req_id: 1,
        app_id: "hello".into(),
        pubkey: "aa11".into(),
        manifest: Some("{}".into()),
    });
    roundtrip(&ClientMsg::AdminGrant {
        req_id: 2,
        subject: Subject::App("hello".into()),
        capability: storage_cap(),
        depth: Depth::N(0),
        expiry: None,
    });
    roundtrip(&ClientMsg::AdminRevoke { req_id: 3, grant_id: "g-1".into() });
    roundtrip(&ClientMsg::AdminList { req_id: 4 });
    roundtrip(&ClientMsg::AdminStartApp { req_id: 5, app_id: "hello".into() });
    roundtrip(&ServerMsg::Granted { req_id: 2, grant_id: "g-1".into() });
    roundtrip(&ServerMsg::AdminState {
        req_id: 4,
        apps: vec![AdminAppInfo {
            app_id: "hello".into(),
            pubkey_hex: "aa11".into(),
            region: "r1".into(),
            surfaces: vec![],
            display_name: None,
            running: false,
            icon: None,
        }],
        records: vec![AdminGrantInfo {
            record: GrantRecord::Revoke { grant: GrantId("g-1".into()), at: 5 },
            effective: false,
            source: "system".into(),
        }],
        daemon_ops: vec![OP_INSTALL_APP.into()],
    });
}

/// D195: the routed install carries the `ui/` bundle (base64 on the wire)
/// and gets a report back; a pre-D195 pvosd's state has no `daemon_ops`.
#[test]
fn d195_install_app_roundtrip_and_wire_shape() {
    let msg = roundtrip(&ClientMsg::AdminInstallApp {
        req_id: 7,
        app_id: "demo".into(),
        pubkey: "aa11".into(),
        manifest: "{}".into(),
        ui: Some(vec![UiFile { path: "assets/a.css".into(), bytes: vec![0, 1, 2, 255] }]),
        take_over: true,
    });
    let v = serde_json::to_value(&msg).unwrap();
    assert_eq!(v["type"], "admin_install_app");
    assert_eq!(v["type"], OP_INSTALL_APP, "the op name IS the wire tag");
    assert_eq!(v["ui"][0], json!({"path": "assets/a.css", "bytes": "AAEC/w=="}));
    assert_eq!(v["take_over"], true, "D204: a marked takeover says so on the wire");
    // No ui/ → the field is absent, and absent decodes as None.
    let bare = roundtrip(&ClientMsg::AdminInstallApp {
        req_id: 8,
        app_id: "demo".into(),
        pubkey: "aa11".into(),
        manifest: "{}".into(),
        ui: None,
        take_over: false,
    });
    let bare_v = serde_json::to_value(&bare).unwrap();
    assert!(bare_v.get("ui").is_none());
    // D204: no takeover → no field, so a pre-D204 pvosd reads it as before.
    assert!(bare_v.get("take_over").is_none());
    // …and a pre-D204 client's message (no field) decodes as "not a takeover".
    match serde_json::from_value::<ClientMsg>(json!({
        "type": "admin_install_app", "req_id": 9, "app_id": "demo",
        "pubkey": "aa11", "manifest": "{}"
    }))
    .unwrap()
    {
        ClientMsg::AdminInstallApp { take_over, .. } => assert!(!take_over),
        other => panic!("decoded as {other:?}"),
    }
    assert!(serde_json::from_value::<UiFile>(json!({"path": "x", "bytes": "not base64!"})).is_err());

    roundtrip(&ServerMsg::AppInstalled {
        req_id: 7,
        app_id: "demo".into(),
        pubkey_hex: "aa11".into(),
        region: "r1".into(),
        ui_root: Some("ab".repeat(32)),
        pvfs_proto: 15,
    });
    let old: ServerMsg =
        serde_json::from_value(json!({"type": "admin_state", "req_id": 1, "apps": [], "records": []}))
            .unwrap();
    assert!(matches!(old, ServerMsg::AdminState { daemon_ops, .. } if daemon_ops.is_empty()));
}

// ── companion agent wire (mirror of pvfs_companion::proto, doc 16) ──────────

#[test]
fn companion_frames_roundtrip_and_pin_shapes() {
    roundtrip(&AgentRequest::ApiVersion);
    roundtrip(&AgentRequest::GetPubkey { role: "identity".into() });
    roundtrip(&AgentRequest::SecureUnwrap {
        ephemeral_pubkey: "02ab".into(),
        nonce: "0011".into(),
        wrapped_key: "ff".into(),
    });
    roundtrip(&AgentResponse::ContentKey { content_key: "aa".repeat(32) });
    roundtrip(&AgentRequest::Sign {
        request_type: "user_action".into(),
        digest: "aa".into(),
        origin: Some("web".into()),
        context: Some(ApprovalContext {
            app_id: "mf".into(),
            action: "grant".into(),
            summary: "mf wants to access storage".into(),
            resource: Some("node-1".into()),
            digest_hex: Some("aa".into()),
        }),
    });
    roundtrip(&AgentResponse::ApiVersion { api_version: AGENT_API_VERSION });
    roundtrip(&AgentResponse::Signature { sig: "bb".into() });
    roundtrip(&AgentResponse::Error { code: "locked".into(), message: "sealed".into() });

    // Pin the doc 16 op/status tagging so we stay wire-compatible.
    assert_eq!(
        serde_json::to_value(AgentRequest::ApiVersion).unwrap(),
        json!({"op": "api_version"})
    );
    assert_eq!(
        serde_json::to_value(AgentResponse::Ok).unwrap(),
        json!({"status": "ok"})
    );
}

// ── M3: view-model + UI + desktop frames (doc 08) ───────────────────────────

#[test]
fn viewmodel_roundtrips_and_pins_doc08_shape() {
    // The doc 08 §4.2 fixture: a table with a row action + a button.
    let vm = ViewModel {
        back: None,
        root: Component::Stack {
            id: None,
            horizontal: false,
            children: vec![
                Component::Heading { text: "Hosts".into() },
                Component::Table {
                    columns: vec!["name".into(), "status".into()],
                    rows: vec![vec!["box1".into(), "up".into()]],
                    row_action: Some("open_host".into()),
                    row_buttons: vec![],
                    row_keys: vec![],
                    time_columns: vec![],
                },
                Component::Button {
                    label: "Refresh".into(),
                    action: "refresh".into(),
                },
            ],
        },
    };
    roundtrip(&vm);
    // Tag shape: type=stack/table/button, snake_case.
    let v = serde_json::to_value(&vm).unwrap();
    assert_eq!(v["root"]["type"], json!("stack"));
    assert_eq!(v["root"]["children"][1]["type"], json!("table"));
    assert_eq!(v["root"]["children"][1]["row_action"], json!("open_host"));

    // Every vocabulary member round-trips.
    roundtrip(&Component::Text { text: "hi".into() });
    roundtrip(&Component::Field {
        id: Some("name".into()),
        label: "Name".into(),
        value: "sam".into(),
        action: Some("edit".into()),
        secret: false,
    });
    // Secret fields render masked; absent on the wire when false.
    let f = Component::Field {
        id: Some("password".into()),
        label: "Password".into(),
        value: String::new(),
        action: None,
        secret: true,
    };
    roundtrip(&f);
    assert_eq!(serde_json::to_value(&f).unwrap()["secret"], json!(true));
    roundtrip(&Component::List { items: vec!["a".into()] });
    roundtrip(&Component::Form {
        action: "submit".into(),
        children: vec![],
        horizontal: false,
    });
    roundtrip(&Component::Alert {
        level: AlertLevel::Warn,
        text: "heads up".into(),
    });
    roundtrip(&Component::Spinner { label: None });
    roundtrip(&Component::Log {
        id: "run".into(),
        lines: vec!["line 1".into()],
    });
    // M4: `tabs` (D10 extend-by-demand — IaC is the consumer).
    let tabs = Component::Tabs {
        id: "console".into(),
        labels: vec!["dashboard".into(), "runs".into()],
        children: vec![
            Component::Text { text: "dash".into() },
            Component::Log { id: "runlog".into(), lines: vec![] },
        ],
        action: Some("tab_switched".into()),
            // Server-requested tab (M6: a notification lands on the right one).
        active: Some(1),
};
    roundtrip(&tabs);
    let v = serde_json::to_value(&tabs).unwrap();
    assert_eq!(v["type"], json!("tabs"));
    assert_eq!(v["labels"][1], json!("runs"));

    // D38: `image` + `card_grid` (the Media app is the consumer).
    roundtrip(&Component::Image {
        src: "/apps/com.x.media/asset/library/movies/Heat (1995)/poster".into(),
        alt: Some("Heat".into()),
    });
    let grid = Component::CardGrid {
        action: "open_title".into(),
        cards: vec![pvos_proto::Card {
            key: "Heat (1995)".into(),
            title: "Heat".into(),
            subtitle: "1995".into(),
            image: Some("/apps/com.x.media/asset/library/movies/Heat (1995)/poster".into()),
        }],
    };
    roundtrip(&grid);
    let v = serde_json::to_value(&grid).unwrap();
    assert_eq!(v["type"], json!("card_grid"));
    assert_eq!(v["cards"][0]["key"], json!("Heat (1995)"));
    // A card with no image serializes lean (the desktop renders a fallback).
    let lean = serde_json::to_value(pvos_proto::Card {
        key: "k".into(),
        title: "T".into(),
        subtitle: String::new(),
        image: None,
    })
    .unwrap();
    assert_eq!(lean.as_object().unwrap().len(), 2);

    // M4a review additions: per-row buttons, select, text_area.
    let t = Component::Table {
        columns: vec!["host".into()],
        rows: vec![vec!["web1".into()]],
        row_action: None,
        row_buttons: vec![RowButton {
            label: "✕".into(),
            action: "delete_server".into(),
            danger: true,
            confirm: Some("Delete this host?".into()),
        }],
        // Stable identity per row — an index alone would let a stale click
        // hit the wrong record (M4a review).
        row_keys: vec!["web1".into()],
        time_columns: vec![],
    };
    roundtrip(&t);
    let v = serde_json::to_value(&t).unwrap();
    assert_eq!(v["row_buttons"][0]["danger"], json!(true));
    assert_eq!(v["row_keys"][0], json!("web1"));
    roundtrip(&Component::Select {
        action: None,
        id: Some("target".into()),
        label: "Target".into(),
        options: vec!["localhost".into(), "web1".into()],
        value: "localhost".into(),
    });
    // M4c: an anchored schedule (the "nightly at 02:00" shape) and the
    // date_time component that produces the anchor.
    let anchored = Schedule::Every {
        interval_ms: 86_400_000,
        first_at_ms: Some(1_800_000_000_000),
    };
    roundtrip(&anchored);
    let v = serde_json::to_value(anchored).unwrap();
    assert_eq!(v["kind"], json!("every"));
    assert_eq!(v["first_at_ms"], json!(1_800_000_000_000u64));
    // The legacy shape must still omit the field entirely (wire-additive).
    let lv = serde_json::to_value(Schedule::Every { interval_ms: 500, first_at_ms: None }).unwrap();
    assert!(lv.get("first_at_ms").is_none(), "unanchored stays clean: {lv}");
    // …and an old payload without the field still parses.
    let parsed: Schedule =
        serde_json::from_value(json!({"kind": "every", "interval_ms": 500})).unwrap();
    assert_eq!(parsed, Schedule::Every { interval_ms: 500, first_at_ms: None });

    let dt = Component::DateTime {
        id: Some("first_at".into()),
        label: "First run".into(),
        value_ms: Some(1_800_000_000_000),
    };
    roundtrip(&dt);
    assert_eq!(serde_json::to_value(&dt).unwrap()["type"], json!("date_time"));

    // `schedule_at` carries the CADENCE, because what a schedule needs to ask
    // depends on it (a time for daily, a weekday + time for weekly) and only
    // the browser knows the owner's timezone (D32).
    let sa = Component::ScheduleAt {
        id: Some("first_at".into()),
        label: "First run".into(),
        cadence: "weekly".into(),
        value_ms: Some(1_800_000_000_000),
    };
    roundtrip(&sa);
    let v = serde_json::to_value(&sa).unwrap();
    assert_eq!(v["type"], json!("schedule_at"));
    assert_eq!(v["cadence"], json!("weekly"));

    // A select may carry a live `action` (fires on change, not on submit) —
    // that is what lets the schedule form re-render around the cadence.
    let live = Component::Select {
        action: Some("pick_cadence".into()),
        id: Some("cadence".into()),
        label: "Cadence".into(),
        options: vec!["daily".into(), "weekly".into()],
        value: "daily".into(),
    };
    roundtrip(&live);
    assert_eq!(serde_json::to_value(&live).unwrap()["action"], json!("pick_cadence"));

    let tg = Component::Toggle {
        id: Some("recursive".into()),
        label: "Include sub-folders".into(),
        value: true,
        action: Some("toggle_recursive".into()),
    };
    roundtrip(&tg);
    assert_eq!(serde_json::to_value(&tg).unwrap()["type"], json!("toggle"));

    let fp = Component::FilePicker {
        id: Some("upload".into()),
        label: "Import a folder".into(),
        action: "import_uploaded".into(),
        directory: true,
        accept: Some(".yml,.yaml".into()),
    };
    roundtrip(&fp);
    let v = serde_json::to_value(&fp).unwrap();
    assert_eq!(v["type"], json!("file_picker"));
    assert_eq!(v["directory"], json!(true));

    let ta = Component::TextArea {
        id: Some("content".into()),
        label: "Playbook YAML".into(),
        value: "---\n".into(),
        language: Some("yaml".into()),
    };
    roundtrip(&ta);
    let tv = serde_json::to_value(&ta).unwrap();
    assert_eq!(tv["type"], json!("text_area"));
    assert_eq!(tv["language"], json!("yaml"));
    // D61 compat both ways: `language: None` stays OFF the wire, and frames
    // from before the field decode fine.
    let plain = Component::TextArea {
        id: None,
        label: "notes".into(),
        value: String::new(),
        language: None,
    };
    assert!(serde_json::to_value(&plain).unwrap().get("language").is_none());
    let old: Component =
        serde_json::from_value(json!({ "type": "text_area", "label": "old" })).unwrap();
    assert!(matches!(old, Component::TextArea { language: None, .. }));
}

#[test]
fn m3_ui_control_messages_roundtrip() {
    // D47: view models ride opaquely — any JSON, typed vocabulary or not.
    let vm = serde_json::to_value(ViewModel { root: Component::Text { text: "x".into() }, back: None })
        .unwrap();
    roundtrip(&ClientMsg::PushViewModel {
        req_id: 1,
        surface: "main".into(),
        view_model: vm,
        actor: Some("a1b2".into()),
    });
    // A pre-D39 push (no actor field) still parses as a broadcast.
    let old: ClientMsg = serde_json::from_str(
        r#"{"type":"push_view_model","req_id":1,"surface":"m","view_model":{"root":{"type":"text","text":"x"}}}"#,
    )
    .unwrap();
    assert!(matches!(old, ClientMsg::PushViewModel { actor: None, .. }));
    roundtrip(&ClientMsg::AppendLog {
        req_id: 2,
        surface: "main".into(),
        component_id: "run".into(),
        lines: vec!["l".into()],
    });
    roundtrip(&ClientMsg::RequestCapability {
        req_id: 3,
        capability: storage_cap(),
        reason: "to save".into(),
    });
    roundtrip(&ServerMsg::UiEvent {
        surface: "main".into(),
        action: "refresh".into(),
        payload: json!(null),
        actor: Some("a1b2".into()),
    });
    // A pre-D31 frame (no actor field) still parses — additive change.
    let old: ServerMsg =
        serde_json::from_str(r#"{"type":"ui_event","surface":"m","action":"x"}"#).unwrap();
    assert!(matches!(old, ServerMsg::UiEvent { actor: None, .. }));
    roundtrip(&ServerMsg::UiLifecycle {
        surface: "main".into(),
        phase: UiPhase::Focus,
        actor: Some("a1b2".into()),
    });
    // A pre-D39 lifecycle (no actor) still parses.
    let old: ServerMsg =
        serde_json::from_str(r#"{"type":"ui_lifecycle","surface":"m","phase":"open"}"#).unwrap();
    assert!(matches!(old, ServerMsg::UiLifecycle { actor: None, .. }));
    assert_eq!(serde_json::to_value(UiPhase::Open).unwrap(), json!("open"));
}

#[test]
fn desktop_ws_frames_roundtrip() {
    roundtrip(&DesktopToServer::Login);
    roundtrip(&DesktopToServer::LoginAnswer {
        pubkey: "aa".into(),
        sig: "bb".into(),
    });
    roundtrip(&DesktopToServer::Authed {
        token: "t".into(),
        action: DesktopAction::List,
    });
    roundtrip(&DesktopToServer::Authed {
        token: "t".into(),
        action: DesktopAction::UiEvent {
            app_id: "greeter".into(),
            surface: "main".into(),
            ui_action: "refresh".into(),
            payload: json!({"x": 1}),
        },
    });
    roundtrip(&DesktopToServer::Authed {
        token: "t".into(),
        action: DesktopAction::ConsentReply { consent_id: 5, approve: true },
    });

    roundtrip(&ServerToDesktop::LoginChallenge {
        digest: "00".into(),
        nonce: "0011".into(),
        instance_id: "forest-1".into(),
        expiry_ms: 99,
        session_pubkey: "02ab".into(),
    });
    // An older frame without the D193 fields still parses.
    let old: ServerToDesktop = serde_json::from_str(r#"{"type":"login_challenge","digest":"00"}"#).unwrap();
    assert!(matches!(old, ServerToDesktop::LoginChallenge { ref nonce, expiry_ms: 0, .. } if nonce.is_empty()));
    roundtrip(&ServerToDesktop::SessionCertRequest {
        member: "kim".into(),
        rp_id: "pvos.example".into(),
        forest_id: "00000000-0000-4000-8000-000000000001".into(),
        root_node_id: "31".into(),
        binding_sig: "aa".into(),
        session_pubkey: "02ab".into(),
    });
    roundtrip(&DesktopToServer::SessionCert { at: 1, expires_at: 2, sigs: vec!["aa".into(), "bb".into()] });
    roundtrip(&ServerToDesktop::BindChallenge { nonce: "00".into(), key: String::new() });
    // PVOS D322: the key the session is bound to, and a frame from an older
    // pvosd without one.
    roundtrip(&ServerToDesktop::BindChallenge { nonce: "00".into(), key: "04ab".into() });
    assert_eq!(
        serde_json::from_str::<ServerToDesktop>(r#"{"type":"bind_challenge","nonce":"00"}"#).unwrap(),
        ServerToDesktop::BindChallenge { nonce: "00".into(), key: String::new() }
    );
    roundtrip(&DesktopToServer::BindProof { sig: "aa".into() });
    roundtrip(&ServerToDesktop::Session { token: "t".into() });
    // D212: the grant, its renewal, and a session that ended.
    roundtrip(&ServerToDesktop::SessionGrant { ends_ms: 9, renew_from_ms: 7, via: "passkey".into() });
    roundtrip(&ServerToDesktop::SessionEnded { reason: "over".into() });
    roundtrip(&DesktopToServer::RenewGrant { token: "t".into() });
    assert_eq!(
        serde_json::to_string(&DesktopToServer::RenewGrant { token: "t".into() }).unwrap(),
        r#"{"type":"renew_grant","token":"t"}"#
    );
    roundtrip(&ServerToDesktop::CompanionLocked);
    roundtrip(&ServerToDesktop::SurfaceUpdate {
        app_id: "greeter".into(),
        surface: "main".into(),
        view_model: serde_json::to_value(ViewModel { root: Component::Text { text: "x".into() }, back: None })
            .unwrap(),
    });
    roundtrip(&ServerToDesktop::ConsentRequest {
        consent_id: 5,
        app_id: "greeter".into(),
        capability: storage_cap(),
        summary: "greeter wants storage".into(),
    });
    // PVOS D209: an unanswered consent's `expired` outcome.
    roundtrip(&ServerToDesktop::ConsentExpired { consent_id: 5, app_id: "greeter".into() });
    assert_eq!(
        serde_json::to_value(ServerToDesktop::ConsentExpired { consent_id: 5, app_id: "g".into() }).unwrap(),
        json!({"type": "consent_expired", "consent_id": 5, "app_id": "g"})
    );
    // Tag pins.
    assert_eq!(
        serde_json::to_value(DesktopToServer::Login).unwrap(),
        json!({"type": "login"})
    );
}

// ── M3.1: pairing + relay (companion proto v2, desktop relay frames) ────────

#[test]
fn pairing_and_relay_types_roundtrip() {
    roundtrip(&pvos_proto::AgentRequest::Pair {
        name: "pvos".into(),
        server_pubkey: "ab".into(),
        origins: vec!["http://x:7420".into()],
    });
    roundtrip(&pvos_proto::AgentRequest::ListPairings);
    roundtrip(&pvos_proto::AgentRequest::RevokePairing { name: "pvos".into() });
    roundtrip(&pvos_proto::AgentResponse::Paired {
        identity_pubkey: "cd".into(),
    });
    roundtrip(&pvos_proto::AgentResponse::Pairings {
        pairings: vec![pvos_proto::PairingInfo {
            name: "pvos".into(),
            server_pubkey_hex: "ab".into(),
            origins: vec!["http://x:7420".into()],
            created_ms: 5,
        }],
    });
    roundtrip(&pvos_proto::RelayPayload {
        kind: "sign_in".into(),
        server_pubkey: "ab".into(),
        digest: "00".repeat(32),
        context: None,
        ..Default::default()
    });
    // D193: the structured kinds, and a companion's JSON for each outcome.
    roundtrip(&pvos_proto::RelayPayload {
        kind: "sign_in".into(),
        server_pubkey: "ab".into(),
        digest: "00".repeat(32),
        login: Some(pvos_proto::LoginFields {
            nonce: "00".into(),
            instance_id: "f".into(),
            expiry_ms: 9,
            session_pubkey: "02ab".into(),
        }),
        ..Default::default()
    });
    roundtrip(&pvos_proto::RelayPayload {
        kind: "confirm".into(),
        server_pubkey: "ab".into(),
        action: Some(pvos_proto::ConfirmFields {
            op: "member_remove".into(),
            subject: "kim".into(),
            detail: String::new(),
            instance_id: "f".into(),
            nonce: "00".into(),
            expiry_ms: 9,
        }),
        ..Default::default()
    });
    let certified: pvos_proto::RelayOutcome =
        serde_json::from_str(r#"{"outcome":"certified","pubkey":"02","at":1,"expires_at":2,"sigs":["a","b"]}"#).unwrap();
    assert!(matches!(certified, pvos_proto::RelayOutcome::Certified { ref sigs, .. } if sigs.len() == 2));
    let genesis: pvos_proto::RelayOutcome = serde_json::from_str(
        r#"{"outcome":"genesis","root":"02","owner":"03","identity":"02","forest_id":"f","instance_id":"pvfs-00000001",
            "created_at":1,"root_nonce":"18446744073709551615","sigs":["a"],"binding_sig":"b"}"#,
    )
    .unwrap();
    assert!(matches!(genesis, pvos_proto::RelayOutcome::Genesis(ref g) if g.root_nonce == "18446744073709551615"));
    roundtrip(&pvos_proto::RelayOutcome::Confirmed { pubkey: "02".into(), sig: "aa".into() });

    roundtrip(&ServerToDesktop::RelayRequest {
        relay_id: 7,
        payload: "{\"kind\":\"sign_in\"}".into(),
        server_sig: "ee".into(),
        code: "066051".into(),
        needs_code: false,
    });
    roundtrip(&DesktopToServer::Authed {
        token: "t".into(),
        action: DesktopAction::GetPrefs,
    });
    roundtrip(&DesktopToServer::Authed {
        token: "t".into(),
        action: DesktopAction::SetPrefs { json: "{\"icons\":{}}".into() },
    });
    roundtrip(&ServerToDesktop::Prefs { json: Some("{\"icons\":{}}".into()) });
    roundtrip(&ServerToDesktop::Prefs { json: None });
    roundtrip(&DesktopToServer::RelayReply {
        relay_id: 7,
        result: pvos_proto::RelayOutcome::Signed {
            pubkey: "cd".into(),
            sig: "ff".into(),
        },
    });
    roundtrip(&DesktopToServer::RelayReply {
        relay_id: 8,
        result: pvos_proto::RelayOutcome::Failed {
            code: "locked".into(),
            message: "sealed".into(),
        },
    });

    // The code derivation is pinned identically to the companion's fixture.
    let mut d = [0u8; 32];
    (d[1], d[2], d[3]) = (0x01, 0x02, 0x03);
    assert_eq!(pvos_proto::verify_code(&d), "066051");
}

// ── D18: invites (signed delegation + redemption) ───────────────────────────

#[test]
fn invite_frames_roundtrip() {
    // Redemption rides the desktop ws, unauthenticated like Login.
    roundtrip(&DesktopToServer::RedeemInvite { code: "ABCD-EFGH".into() });
    roundtrip(&ServerToDesktop::RedeemChallenge {
        invite_id: "inv-1".into(),
        member: "kim".into(),
        email: "kim@example.com".into(),
        role: "member".into(),
        capabilities: vec!["use_shared_apps".into()],
        invited_by: "sam".into(),
        server_pubkey: "ab".into(),
        origins: vec!["https://pvos.example:7420".into()],
        browser_available: true,
        rekey: false,
        personal_host: "02aa".into(),
    });
    roundtrip(&DesktopToServer::RedeemAnswer {
        invite_id: "inv-1".into(),
        pubkey: "cd".into(),
        sig: "ee".into(),
    });
    roundtrip(&DesktopToServer::RedeemPersonal {
        invite_id: "inv-1".into(),
        identity: "03cd".into(),
        root: "02ef".into(),
        owner: "02dd".into(),
        sig: "ee".into(),
        genesis: pvos_proto::desktop::PersonalGenesis {
            forest_id: "00000000-0000-4000-8000-000000000001".into(),
            instance_id: "pvfs-00000001".into(),
            created_at: 1_700_000_000_000,
            root_nonce: u64::MAX.to_string(),
            sigs: vec!["aa".into(); 5],
        },
        blob: "b64ciphertext".into(),
        binding_sig: "cc".into(),
    });
    // The page's JSON, as it sends it: a u64 nonce as a decimal string.
    let from_page: DesktopToServer = serde_json::from_str(
        r#"{"type":"redeem_personal","invite_id":"i","identity":"03","root":"02","owner":"02","sig":"s",
            "genesis":{"forest_id":"f","instance_id":"pvfs-00000001","created_at":1700000000000,
                       "root_nonce":"18446744073709551615","sigs":["a","b","c","d","e"]},"blob":"b","binding_sig":"c"}"#,
    )
    .unwrap();
    assert!(matches!(from_page, DesktopToServer::RedeemPersonal { ref genesis, .. } if genesis.root_nonce == "18446744073709551615"));
    roundtrip(&DesktopToServer::BrowserBlobGet { member: "kim".into() });
    roundtrip(&pvos_proto::ClientMsg::AdminMemberSetRole {
        req_id: 9,
        member: "kim".into(),
        role: "admin".into(),
    });
    roundtrip(&pvos_proto::ClientMsg::AdminMemberRekey { req_id: 10, member: "kim".into() });
    roundtrip(&pvos_proto::ClientMsg::AdminMemberSetAppActions {
        req_id: 12,
        member: "kim".into(),
        app_id: "monitoring".into(),
        actions: vec!["acknowledge".into()],
    });
    roundtrip(&pvos_proto::ClientMsg::AdminMemberArchiveData { req_id: 11, member: "kim".into() });
    roundtrip(&DesktopToServer::LoginBrowser { member: "kim".into() });
    roundtrip(&ServerToDesktop::BrowserBlob {
        blob: "b64ciphertext".into(),
        member: "kim".into(),
    });
    roundtrip(&DesktopToServer::BrowserBlobByCred { cred: "Y3JlZA==".into() });
    roundtrip(&ServerToDesktop::Redeemed { member: "kim".into() });

    // Admin channel: create/list/revoke. The code appears ONLY in
    // InviteCreated — InviteInfo never carries it.
    roundtrip(&ClientMsg::AdminInviteCreate {
        req_id: 1,
        member: "kim".into(),
        email: "kim@example.com".into(),
        role: "member".into(),
        ttl_ms: Some(60_000),
    });
    roundtrip(&ClientMsg::AdminInviteList { req_id: 2 });
    roundtrip(&ClientMsg::AdminInviteRevoke { req_id: 3, invite_id: "inv-1".into() });
    roundtrip(&ServerMsg::InviteCreated {
        reattach_warning: true,
        req_id: 1,
        invite_id: "inv-1".into(),
        code: "ABCD-EFGH-IJKL-MNOP-QRST-UVWX".into(),
        expires_ms: 99,
        emailed: true,
    });
    let info = pvos_proto::InviteInfo {
        purpose: "join".into(),
        invite_id: "inv-1".into(),
        member: "kim".into(),
        email: "kim@example.com".into(),
        role: "member".into(),
        state: "pending".into(),
        created_ms: 1,
        expires_ms: 99,
        inviter: "sam".into(),
        redeemed_ms: None,
    };
    roundtrip(&ServerMsg::InviteList { req_id: 2, invites: vec![info.clone()] });
    // Pin: a listed invite must not have a "code" field at all.
    let v = serde_json::to_value(&info).unwrap();
    assert!(v.get("code").is_none());
}

// ── D18 slice 4: role subjects, shares, per-member notifications ───────────

#[test]
fn role_subjects_and_share_frames_roundtrip() {
    // Subject::Role — "shared with every holder of this role" — is an
    // ordinary subject with the wire form the others use.
    let role = Subject::Role("member".into());
    assert_eq!(serde_json::to_value(&role).unwrap(), json!("role:member"));
    assert_eq!(Subject::parse("role:member").unwrap(), role);
    roundtrip(&role);
    roundtrip(&GrantRecord::Grant(Grant {
        id: GrantId("share-1".into()),
        subject: Subject::Role("member".into()),
        capability: Capability {
            kind: CapKind::Ui,
            scope: Scope::Ui { surfaces: vec!["greeter".into()] },
        },
        issuer: Issuer::Owner,
        redelegation_depth: Depth::N(0),
        expiry: None,
        issued_at: 1,
    }));
    roundtrip(&ClientMsg::AdminShare {
        req_id: 1,
        app_id: "greeter".into(),
        role: "member".into(),
    });
    roundtrip(&ClientMsg::AdminUnshare {
        req_id: 2,
        app_id: "greeter".into(),
        role: "member".into(),
    });

    // The manifest's admin-only marker: absent = false (every existing
    // manifest keeps meaning what it meant).
    let m: pvos_proto::AppManifest = serde_json::from_value(json!({
        "id": "iac", "version": "1", "api_version": 1, "display_name": "IaC",
        "tier": "user", "residency": "integrated", "admin_only": true,
        "runtime": {"kind": "native", "entrypoint": "/bin/iac"}
    }))
    .unwrap();
    assert!(m.admin_only);
    // And absent = false.
    let m: pvos_proto::AppManifest = serde_json::from_value(json!({
        "id": "g", "version": "1", "api_version": 1, "display_name": "G",
        "tier": "user", "residency": "integrated",
        "runtime": {"kind": "native", "entrypoint": "/bin/g"}
    }))
    .unwrap();
    assert!(!m.admin_only);

    // A pre-D18 notification (no member field) belongs to the owner.
    let n: pvos_proto::notify::Notification = serde_json::from_value(json!({
        "id": "n-1", "seq": 1, "app": "iac", "level": "info",
        "title": "t", "created_ms": 1
    }))
    .unwrap();
    assert_eq!(n.member, "owner");
    roundtrip(&n);
}

// ── D18 slice 5: membership frames ──────────────────────────────────────────

#[test]
fn member_management_frames_roundtrip() {
    roundtrip(&ClientMsg::AdminMemberList { req_id: 1 });
    roundtrip(&ClientMsg::AdminMemberInspect { req_id: 2, member: "bob".into() });
    roundtrip(&ClientMsg::AdminMemberRemove { req_id: 3, member: "bob".into() });
    roundtrip(&ClientMsg::AdminMemberSetEmail {
        req_id: 4,
        member: "bob".into(),
        email: "bob@example.com".into(),
    });
    roundtrip(&ServerMsg::MemberList {
        req_id: 1,
        members: vec![pvos_proto::MemberInfo {
            member: "kim".into(),
            role: "member".into(),
            custody: "remote".into(),
            invited_by: Some("alice".into()),
            paired_at_ms: 9,
            email: Some("kim@example.com".into()),
            email_verified: false,
            app_actions: [("com.turnernetworking.monitoring".to_string(), vec!["acknowledge".to_string()])].into(),
        }],
    });
    roundtrip(&ServerMsg::MemberImpact {
        req_id: 2,
        member: "bob".into(),
        sessions: 1,
        pending_invites: vec![],
        invited_members: vec!["pat".into()],
    });
}

// ── M3.5: Mode A bridge frames ──────────────────────────────────────────────

#[test]
fn bridge_frames_roundtrip() {
    use pvos_proto::desktop::BridgeOp;
    use pvos_proto::DesktopAction;
    // BridgeCall is a DesktopAction (carried inside Authed).
    roundtrip(&DesktopAction::BindSession { key: "04ab".into() });
    roundtrip(&DesktopAction::AddPasskey { blob: "eyJ2IjozfQ==".into() });
    roundtrip(&DesktopAction::BridgeCall {
        req_id: 3,
        app_id: "mediaforest".into(),
        surface: "library".into(),
        op: BridgeOp::Notify { level: "info".into(), text: "hi".into() },
    });
    roundtrip(&DesktopToServer::Authed {
        token: "t".into(),
        action: DesktopAction::BridgeCall {
            req_id: 4,
            app_id: "m".into(),
            surface: "s".into(),
            op: BridgeOp::OpenApp { app_id: "greeter".into() },
        },
    });
    roundtrip(&BridgeOp::RequestCapability {
        capability: storage_cap(),
        reason: "to save".into(),
    });
    roundtrip(&BridgeOp::DiscoverServices { query: Some("media".into()) });
    roundtrip(&BridgeOp::OpenApp { app_id: "greeter".into() });
    roundtrip(&ServerToDesktop::BridgeReply {
        req_id: 3,
        app_id: "mediaforest".into(),
        ok: true,
        payload: json!({"grant_id": "g-1"}),
    });
    // AdminAppInfo carries surfaces (mode) for the desktop's renderer choice.
    let info = pvos_proto::AdminAppInfo {
        app_id: "mediaforest".into(),
        pubkey_hex: "ab".into(),
        region: "node-1".into(),
        surfaces: vec![pvos_proto::manifest::UiSurface {
            name: "library".into(),
            mode: pvos_proto::manifest::SurfaceMode::Iframe,
            entry: Some("served".into()),
        }],
        display_name: Some("Mediaforest".into()),
        // The desktop shows a live dot and gates "force quit" on this.
        running: true,
        // PVOS D209: the icon route, when the manifest declares one.
        icon: Some("/apps/mediaforest/icon".into()),
    };
    roundtrip(&info);
    let v = serde_json::to_value(&info).unwrap();
    assert_eq!(v["surfaces"][0]["mode"], json!("iframe"));
    assert_eq!(v["icon"], json!("/apps/mediaforest/icon"));
    // PVOS D209: a pvosd from before icons sends no `icon`; it decodes.
    let mut old = v.clone();
    old.as_object_mut().unwrap().remove("icon");
    let back: pvos_proto::AdminAppInfo = serde_json::from_value(old).unwrap();
    assert_eq!(back.icon, None);
}


// ── D30: the Settings surface ───────────────────────────────────────────────

#[test]
fn settings_frames_roundtrip() {
    use pvos_proto::desktop::{
        AppShareView, ImpactView, LogDestinationEdit, LogDestinationView, LogLevelView, LoggingView, MailView,
        SessionView, SettingsOp, SettingsState, ShareView,
    };
    // D222d: one destination as the Settings form edits it.
    let dest = LogDestinationEdit {
        name: "siem".into(),
        kind: "syslog".into(),
        enabled: true,
        target: "siem.corp:6514".into(),
        transport: "tls".into(),
        format: "cef".into(),
        index: String::new(),
        privacy: "minimal".into(),
        min_severity: "info".into(),
        categories: vec!["audit".into(), "security".into()],
        tls_ca_file: String::new(),
        tls_pin_sha256: "AB:CD".into(),
        labels: "env=prod".into(),
        doc_ids: false,
    };
    for op in [
        SettingsOp::Get,
        SettingsOp::MemberInspect { member: "bob".into() },
        SettingsOp::MemberRemove { member: "bob".into() },
        SettingsOp::MemberSetEmail { member: "bob".into(), email: "b@x.co".into() },
        SettingsOp::InviteCreate {
            member: "kim".into(),
            email: "kim@x.co".into(),
            role: "member".into(),
        },
        SettingsOp::InviteRevoke { invite_id: "inv-1".into() },
        SettingsOp::SessionRevoke { id: "s-1".into() },
        SettingsOp::Share { app_id: "greeter".into(), role: "member".into() },
        SettingsOp::Unshare { app_id: "greeter".into(), role: "member".into() },
        SettingsOp::MailSet {
            host: "smtp.gmail.com".into(),
            port: 587,
            security: "starttls".into(),
            username: "u@x.co".into(),
            from: "PVOS <u@x.co>".into(),
            password: Some("pw".into()),
        },
        SettingsOp::MailTest { to: "u@x.co".into() },
        SettingsOp::LogSet { original: Some("old".into()), dest: dest.clone(), token: Some("t0k".into()) },
        SettingsOp::LogSet { original: None, dest: dest.clone(), token: None },
        SettingsOp::LogRemove { name: "siem".into() },
        SettingsOp::LogTest { name: "siem".into() },
        SettingsOp::LogLevelSet { level: "debug".into(), minutes: 5 },
    ] {
        roundtrip(&DesktopToServer::Authed {
            token: "t".into(),
            action: DesktopAction::Settings { op },
        });
    }
    let state = SettingsState {
        can_members: true,
        can_sharing: true,
        can_sessions: true,
        can_mail: true,
        members: vec![],
        invites: vec![],
        sessions: vec![SessionView {
            id: "s-1".into(),
            member: "alice".into(),
            label: "Safari".into(),
            last_seen_ms: 5,
            expires_ms: 9,
        }],
        shares: vec![ShareView { app_id: "greeter".into(), role: "member".into() }],
        apps: vec![AppShareView {
            app_id: "iac".into(),
            display_name: Some("IaC".into()),
            admin_only: true,
            member_actions: vec![pvos_proto::manifest::MemberAction {
                name: "plan".into(),
                description: "Run a plan".into(),
            }],
        }],
        mail: Some(MailView {
            host: "smtp.gmail.com".into(),
            port: 587,
            security: "starttls".into(),
            username: "u@x.co".into(),
            from: "u@x.co".into(),
        }),
        impact: Some(ImpactView {
            member: "bob".into(),
            sessions: 1,
            pending_invites: vec![],
            invited_members: vec!["pat".into()],
        }),
        can_mounts: false,
        mounts: None,
        can_logging: true,
        logging: Some(LoggingView {
            destinations: vec![LogDestinationView {
                dest: dest.clone(),
                has_token: true,
                sent: 12,
                queued_bytes: 0,
                dropped: 0,
                last_ok_ms: 1_700_000_000_000,
                last_error: String::new(),
                failing: false,
            }],
            log_level: LogLevelView { configured: "info".into(), current: "debug".into(), until_ms: Some(1_700_000_060_000) },
        }),
        // PVOS D262: DNS for PVOS apps.
        can_dns: true,
        dns: Some(pvos_proto::desktop::DnsView {
            config: Some(json!({ "split": [{ "domains": ["home.test"], "bare_names": true, "servers": ["192.0.2.53:53"] }], "default": [] })),
            host_resolvers: vec!["127.0.0.53".into()],
            notice: "This changes DNS for PVOS apps only.".into(),
        }),
        dns_answer: Some(json!({ "name": "logs.home.test", "addresses": ["10.9.8.7"], "via": "192.0.2.53:53", "fell_back": false, "nxdomain": false })),
        // PVOS D264: notification settings.
        can_notify: true,
        notify: Some(pvos_proto::desktop::NotifyView {
            routing: Some(json!({ "version": 1700000000000u64,
                "destinations": [{ "name": "Sam", "kind": "telegram", "chat": "-100200300" }],
                "routes": { "page": ["Sam"], "summary": [], "digest": ["Sam"] } })),
            applied: Some(pvos_proto::desktop::RoutingApplied { version: 1700000000000, at_ms: 1700000000500, by: "monitoring".into() }),
        }),
    };
    // The password never appears in the STATE — write-only by construction
    // (and a log destination's token neither: only `has_token`).
    let json = serde_json::to_string(&state).unwrap();
    assert!(!json.contains("password"), "{json}");
    assert!(!json.contains("t0k"), "{json}");
    roundtrip(&ServerToDesktop::Settings { state: Box::new(state) });
    roundtrip(&ServerToDesktop::InviteMinted {
        member: "kim".into(),
        email: "kim@x.co".into(),
        role: "member".into(),
        code: None,
        emailed: true,
        reattach_warning: false,
    });
}

// ── D64: the PVFS mounts panel ──────────────────────────────────────────────

#[test]
fn d64_mounts_frames_roundtrip() {
    use pvos_proto::desktop::{
        BindingView, ForestView, InstanceView, MountsView, SettingsOp, SettingsState,
    };
    for op in [
        SettingsOp::MountBind {
            mount: "/home/sam/pvos-system".into(),
            folder: "/media/import".into(),
            dir: "/mnt/ingest".into(),
            kind: "migrate".into(),
            store: Some("/tank/store".into()),
            recursive: true,
            auto_index: true,
            extensions: "mkv,mp4".into(),
            hash_policy: "on_add".into(),
        },
        SettingsOp::MountUnbind {
            mount: "/home/sam/pvos-system".into(),
            folder_id: "node-7".into(),
        },
        SettingsOp::MountScan {
            mount: "/home/sam/pvos-system".into(),
            folder_id: None,
        },
        // D70: serving a forest as a supervised child.
        SettingsOp::ForestServe { mount: "/home/sam/pvfs-test".into() },
        SettingsOp::ForestStop { mount: "/home/sam/pvfs-test".into() },
        SettingsOp::ForestServeAtBoot { mount: "/home/sam/pvfs-test".into(), on: true },
        SettingsOp::InstanceAdd {
            name: "box2".into(),
            addr: "feeder.example:7420".into(),
            pin: "ab".repeat(32),
        },
        SettingsOp::InstanceRemove { name: "box2".into() },
        SettingsOp::ReplicaAdd {
            dest: "/srv/replicas/feeder".into(),
            instance: "box2".into(),
            region: None,
        },
    ] {
        roundtrip(&DesktopToServer::Authed {
            token: "t".into(),
            action: DesktopAction::Settings { op },
        });
    }
    let state = SettingsState {
        can_mounts: true,
        mounts: Some(MountsView {
            forests: vec![ForestView {
                alias: Some("system".into()),
                mount: "/home/sam/pvos-system".into(),
                forest_id: "f3a9c1d2e4b5".into(),
                is_system: true,
                registered: true,
                enabled: true,
                is_replica: false,
                replica_source: None,
                served: true,
                // D70: a forest PVOS is supervising — `served` says a daemon
                // answers, `serve_state` says it is one of ours.
                serve_state: Some("served".into()),
                serve_secs: 42,
                serve_error: None,
                serve_at_boot: true,
                bindings: vec![BindingView {
                    folder_id: "node-7".into(),
                    folder_path: Some("/media/import".into()),
                    source: "/mnt/ingest".into(),
                    kind: "migrate".into(),
                    store: Some("/tank/store".into()),
                    recursive: true,
                    auto_index: true,
                    extensions: String::new(),
                    hash_policy: "on_add".into(),
                    bound_at_ms: 5,
                }],
                note: None,
            }],
            instances: vec![InstanceView {
                name: "box2".into(),
                addr: "feeder.example:7420".into(),
                pin_prefix: "ababababab…".into(),
            }],
            note: None,
        }),
        ..Default::default()
    };
    roundtrip(&ServerToDesktop::Settings { state: Box::new(state) });
    // A pre-D64 frame (no mounts fields) still decodes — additive, tolerant.
    let old: SettingsState = serde_json::from_str(
        "{\"can_members\":false,\"can_sharing\":false,\"can_sessions\":false,\"can_mail\":false}",
    )
    .unwrap();
    assert!(!old.can_mounts && old.mounts.is_none());
}

#[test]
fn d262_dns_messages_on_the_wire() {
    use pvos_proto::desktop::SettingsOp;
    let cfg = json!({ "split": [{ "domains": ["home.test"], "bare_names": false, "servers": ["192.0.2.53"] }], "default": ["192.0.2.1"] });
    roundtrip(&SettingsOp::DnsSet { config: cfg.clone() });
    roundtrip(&SettingsOp::DnsClear);
    roundtrip(&SettingsOp::DnsLookup { name: "logs".into() });
    let from_page: SettingsOp = serde_json::from_str(r#"{"op":"dns_lookup","name":"logs"}"#).unwrap();
    assert_eq!(from_page, SettingsOp::DnsLookup { name: "logs".into() });
    roundtrip(&pvos_proto::ClientMsg::AdminDnsSet { req_id: 1, config: Some(cfg.clone()) });
    roundtrip(&pvos_proto::ClientMsg::AdminDnsSet { req_id: 2, config: None });
    roundtrip(&pvos_proto::ClientMsg::AdminDnsShow { req_id: 3 });
    roundtrip(&pvos_proto::ServerMsg::DnsSetting {
        req_id: 3,
        config: Some(cfg),
        host_resolvers: vec!["127.0.0.53".into()],
        notice: "n".into(),
    });
}

#[test]
fn d264_notification_routing_on_the_wire() {
    use pvos_proto::desktop::SettingsOp;
    let r = json!({ "destinations": [{ "name": "Sam", "kind": "telegram", "chat": "-100200300" }],
                    "routes": { "page": ["Sam"], "summary": [], "digest": [] } });
    roundtrip(&SettingsOp::NotifyRoutingSet { routing: r.clone() });
    let from_page: SettingsOp = serde_json::from_value(json!({ "op": "notify_routing_set", "routing": r.clone() })).unwrap();
    assert_eq!(from_page, SettingsOp::NotifyRoutingSet { routing: r.clone() });
    roundtrip(&pvos_proto::ClientMsg::AdminNotifyRoutingShow { req_id: 1 });
    roundtrip(&pvos_proto::ClientMsg::AdminNotifyRoutingSet { req_id: 2, routing: r.clone() });
    roundtrip(&pvos_proto::ServerMsg::NotifyRouting { req_id: 1, routing: Some(r) });
    roundtrip(&pvos_proto::ServerMsg::NotifyRouting { req_id: 3, routing: None });
}

#[test]
fn d290_mounts_on_the_wire() {
    roundtrip(&pvos_proto::ClientMsg::AdminMounts {
        req_id: 1,
        action: "show".into(),
        args: json!({}),
    });
    roundtrip(&pvos_proto::ServerMsg::MountsReport {
        req_id: 1,
        summary: String::new(),
        view: Some(pvos_proto::desktop::MountsView::default()),
    });
    roundtrip(&pvos_proto::ServerMsg::MountsReport {
        req_id: 2,
        summary: "bound pics".into(),
        view: None,
    });
    roundtrip(&pvos_proto::ClientMsg::AdminTokenCreate {
        req_id: 1,
        label: "home".into(),
        operations: vec!["mounts.show".into()],
        app: None,
        ttl_ms: 3_600_000,
    });
    roundtrip(&pvos_proto::ServerMsg::TokenCreated {
        req_id: 1,
        token_id: "tok-1".into(),
        secret: "once".into(),
        expires_ms: 10,
    });
    roundtrip(&pvos_proto::ServerMsg::TokenList {
        req_id: 2,
        tokens: vec![pvos_proto::ApiTokenInfo {
            id: "tok-1".into(),
            label: String::new(),
            operations: vec!["mounts.show".into()],
            app: None,
            expires_ms: 10,
            created_by: "alice".into(),
        }],
    });
}
