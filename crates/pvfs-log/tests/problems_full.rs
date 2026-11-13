//! PVOS D332 — the problems file keeps full detail when the process logs at
//! `identified`: the journal leaves the box (Alloy → Loki), this file does
//! not. Its own binary, so the privacy level is set before the logger starts.

use pvfs_log::{content, problems, pv_warn, Privacy};

#[test]
fn the_problems_file_is_full_when_the_journal_is_identified() {
    std::env::set_var("PVFS_LOG_PRIVACY", "identified");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(problems::FILE_NAME);
    problems::open(path.clone());

    pv_warn!("pvfs.test.d332", path = content("/home/alice/notes.txt"), error_kind = "other";
        "pvfsd: cannot read /home/alice/notes.txt");

    let (recs, _) = problems::read_since(&path, 0, 10);
    let rec = recs.iter().find(|r| r.event == "pvfs.test.d332").expect("the warning is in the file");
    assert_eq!(rec.line(), "pvfsd: cannot read /home/alice/notes.txt", "full detail in the file");

    // What the journal shows of the same record at `identified`: the path is out.
    let view = pvfs_log::render(rec, Privacy::Identified, None);
    assert!(!view.line().contains("/home/alice/notes.txt"), "the journal hides it: {}", view.line());
}
