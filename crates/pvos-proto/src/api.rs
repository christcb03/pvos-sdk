//! PVOS D290 — one name for each operation the CLI, the desktop, and a
//! later REST listener call. An entry describes authority. It does not
//! perform the operation; the handler it names already exists.

/// Who may call the operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authority {
    /// The owner, on the local control socket or a signed-in owner session.
    Owner,
    /// The owner or an admin (`manage_apps`).
    ManageApps,
}

/// What a reply may contain of a secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretPolicy {
    /// The operation does not touch a secret.
    None,
    /// A caller may store a value. A reply never carries it back.
    WriteOnly,
    /// Only the local CLI, on the owner socket, may read the value.
    LocalCliOnly,
}

/// Whether the reply is the result, or an id to follow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    Sync,
    Job,
}

/// One controllable operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Operation {
    /// `group.name`, the catalog id. The CLI spells the same words.
    pub id: &'static str,
    pub summary: &'static str,
    pub authority: Authority,
    /// The companion still signs this, from a shell or from HTTP.
    pub companion: bool,
    pub secret: SecretPolicy,
    pub shape: Shape,
}

/// Operations with a handler. The table grows as a command lands; a name
/// here is callable, not a plan.
pub static OPERATIONS: &[Operation] = &[
    Operation {
        id: "notify.routing.show",
        summary: "who receives pages, summaries, and the digest",
        authority: Authority::ManageApps,
        companion: false,
        secret: SecretPolicy::None,
        shape: Shape::Sync,
    },
    Operation {
        id: "notify.routing.set",
        summary: "save who receives pages, summaries, and the digest",
        authority: Authority::ManageApps,
        companion: false,
        secret: SecretPolicy::None,
        shape: Shape::Sync,
    },
    Operation {
        id: "mounts.show",
        summary: "forests, enrollments, and remote instances",
        authority: Authority::Owner,
        companion: false,
        secret: SecretPolicy::None,
        shape: Shape::Sync,
    },
    Operation {
        id: "mounts.bind",
        summary: "enroll a host directory in a forest",
        authority: Authority::Owner,
        companion: false,
        secret: SecretPolicy::None,
        shape: Shape::Sync,
    },
    Operation {
        id: "mounts.unbind",
        summary: "end an enrollment; the files stay",
        authority: Authority::Owner,
        companion: false,
        secret: SecretPolicy::None,
        shape: Shape::Sync,
    },
    Operation {
        id: "mounts.scan",
        summary: "scan an enrollment against its directory",
        authority: Authority::Owner,
        companion: false,
        secret: SecretPolicy::None,
        shape: Shape::Sync,
    },
    Operation {
        id: "forests.serve",
        summary: "serve a forest as a child of pvosd",
        authority: Authority::Owner,
        companion: false,
        secret: SecretPolicy::None,
        shape: Shape::Sync,
    },
    Operation {
        id: "forests.stop",
        summary: "stop a forest daemon pvosd started",
        authority: Authority::Owner,
        companion: false,
        secret: SecretPolicy::None,
        shape: Shape::Sync,
    },
    Operation {
        id: "forests.boot",
        summary: "serve a forest again when pvosd starts",
        authority: Authority::Owner,
        companion: false,
        secret: SecretPolicy::None,
        shape: Shape::Sync,
    },
    Operation {
        id: "forests.register",
        summary: "add a forest to this host's registry",
        authority: Authority::Owner,
        companion: false,
        secret: SecretPolicy::None,
        shape: Shape::Sync,
    },
    Operation {
        id: "forests.unregister",
        summary: "drop a forest from this host's registry",
        authority: Authority::Owner,
        companion: false,
        secret: SecretPolicy::None,
        shape: Shape::Sync,
    },
    Operation {
        id: "instances.add",
        summary: "remember a remote instance and its pin",
        authority: Authority::Owner,
        companion: false,
        secret: SecretPolicy::WriteOnly,
        shape: Shape::Sync,
    },
    Operation {
        id: "instances.remove",
        summary: "forget a remote instance",
        authority: Authority::Owner,
        companion: false,
        secret: SecretPolicy::None,
        shape: Shape::Sync,
    },
    Operation {
        id: "replica.add",
        summary: "start a local replica of a remote forest",
        authority: Authority::Owner,
        companion: false,
        secret: SecretPolicy::None,
        shape: Shape::Sync,
    },
    Operation {
        id: "tokens.create",
        summary: "mint a scoped token; the companion signs it",
        authority: Authority::Owner,
        companion: true,
        secret: SecretPolicy::WriteOnly,
        shape: Shape::Sync,
    },
    Operation {
        id: "tokens.list",
        summary: "the scoped tokens, without their secrets",
        authority: Authority::Owner,
        companion: false,
        secret: SecretPolicy::None,
        shape: Shape::Sync,
    },
    Operation {
        id: "tokens.revoke",
        summary: "end a scoped token at once",
        authority: Authority::Owner,
        companion: false,
        secret: SecretPolicy::None,
        shape: Shape::Sync,
    },
    Operation {
        id: "apps.methods",
        summary: "API methods installed apps declare",
        authority: Authority::Owner,
        companion: false,
        secret: SecretPolicy::None,
        shape: Shape::Sync,
    },
];

/// Whether a scoped token may be given `op`. A token cannot wait on the
/// companion, mint another token, or mint a grant.
pub fn token_may_name(op: &Operation) -> Result<(), &'static str> {
    if op.companion {
        return Err("that operation waits on the companion; a token cannot call it");
    }
    if op.id.starts_with("tokens.") {
        return Err("a token cannot mint or revoke tokens");
    }
    if op.id.contains("grant") {
        return Err("a token cannot mint a grant");
    }
    Ok(())
}

/// The entry for `id`, if a handler exists.
pub fn get(id: &str) -> Option<&'static Operation> {
    OPERATIONS.iter().find(|op| op.id == id)
}

/// OpenAPI 3 document for the operations that have a handler. The path is
/// `POST /api/<id>`. The body is that operation's arguments. A reply is the
/// result, or a sentence when the work only reports what it did.
pub fn openapi() -> serde_json::Value {
    let mut paths = serde_json::Map::new();
    for op in OPERATIONS {
        let authority = match op.authority {
            Authority::Owner => "owner",
            Authority::ManageApps => "manage_apps",
        };
        let secret = match op.secret {
            SecretPolicy::None => "none",
            SecretPolicy::WriteOnly => "write_only",
            SecretPolicy::LocalCliOnly => "local_cli_only",
        };
        let shape = match op.shape {
            Shape::Sync => "sync",
            Shape::Job => "job",
        };
        paths.insert(
            format!("/api/{}", op.id),
            serde_json::json!({
                "post": {
                    "operationId": op.id,
                    "summary": op.summary,
                    "x-pvos-authority": authority,
                    "x-pvos-companion": op.companion,
                    "x-pvos-secret": secret,
                    "x-pvos-shape": shape,
                }
            }),
        );
    }
    serde_json::json!({
        "openapi": "3.0.3",
        "info": { "title": "PVOS", "version": "1" },
        "paths": paths,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_is_named_and_does_not_wait_on_the_companion() {
        let show = get("notify.routing.show").expect("show");
        let set = get("notify.routing.set").expect("set");
        assert_eq!(show.authority, Authority::ManageApps);
        assert!(!show.companion && !set.companion);
        assert_eq!(set.secret, SecretPolicy::None);
        assert_eq!(set.shape, Shape::Sync);
        assert!(get("notify.routing.apply").is_none());
        let bind = get("mounts.bind").expect("bind");
        assert_eq!(bind.authority, Authority::Owner);
        assert!(!bind.companion);
        assert_eq!(get("instances.add").expect("add").secret, SecretPolicy::WriteOnly);
        assert_eq!(get("replica.add").expect("replica").shape, Shape::Sync);
        assert!(get("mounts.apply").is_none());
    }

    #[test]
    fn the_document_names_every_operation() {
        let doc = openapi();
        let paths = doc["paths"].as_object().expect("paths");
        for op in OPERATIONS {
            let path = format!("/api/{}", op.id);
            let post = &paths[&path]["post"];
            assert_eq!(post["operationId"], op.id);
            assert_eq!(post["summary"], op.summary);
        }
        assert_eq!(doc["paths"]["/api/mounts.bind"]["post"]["x-pvos-authority"], "owner");
        assert_eq!(doc["paths"]["/api/instances.add"]["post"]["x-pvos-secret"], "write_only");
        assert_eq!(doc["paths"]["/api/notify.routing.show"]["post"]["x-pvos-companion"], false);
        assert!(get("tokens.create").expect("create").companion);
        assert!(token_may_name(get("mounts.show").unwrap()).is_ok());
        assert!(token_may_name(get("tokens.create").unwrap()).is_err());
        assert!(token_may_name(get("tokens.revoke").unwrap()).is_err());
    }
}
