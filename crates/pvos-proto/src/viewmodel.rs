//! The server-driven view-model (doc 08 §4): an app describes a UI surface as
//! a serializable [`Component`] tree of a fixed vocabulary; the desktop renders
//! it with native components. Apps ship no front-end (Mode B).
//!
//! The vocabulary grows only when a consumer needs a component (D10, adopted
//! 2026-07-10 with `stack, heading, text, field, button, list, table, form,
//! alert, spinner, log`). Since then: `tabs, toggle, select, text_area,
//! file_picker, date_time, schedule_at, chart` (M4-era), `image, card_grid`
//! (D38 Media), `segmented, combo` (D42/D44 browse filters — combo
//! carries the chip/multi-select mode), `link` (D58 — Play on Plex),
//! `diagram` (D248 — boxes the viewer drags and resizes), and `file_pane`
//! (D286 — one pane of the Files app; the desktop keeps the selection).
//! `grid` and `icon` remain unclaimed.
//! Streaming append is the `log` component, fed incrementally by `AppendLog`
//! (D2) rather than a full re-push. pvosd relays view models opaquely (D47:
//! `PushViewModel.view_model` is a JSON value), so a new component needs a
//! desktop that draws it, not a new pvosd.

use serde::{Deserialize, Serialize};

/// A UI component. `type`-tagged, snake_case (doc 08 §4.2). Optional `id` keys
/// a node for reconciliation + targets `AppendLog`. `action` ids come back as
/// `UiEvent`s.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Component {
    /// Vertical (default) or horizontal container.
    Stack {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        #[serde(default)]
        horizontal: bool,
        children: Vec<Component>,
    },
    Heading {
        text: String,
    },
    Text {
        text: String,
    },
    /// A labeled input bound to `value`; edits emit `action` with the new value.
    /// `secret` renders masked (password) with a reveal toggle (M4a).
    Field {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        label: String,
        #[serde(default)]
        value: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        action: Option<String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        secret: bool,
    },
    Button {
        label: String,
        action: String,
    },
    List {
        items: Vec<String>,
    },
    /// Tabular data. `row_action` and `row_buttons` fire with
    /// `{row: index, key: row_keys[index]}`.
    ///
    /// **Always set `row_keys`** when the action mutates something: an index
    /// is a position in a snapshot the user was looking at, and by the time
    /// the event arrives the collection may have changed (a concurrent push,
    /// a second click while a confirm dialog was up, another desktop
    /// session). Resolving by index then hits the WRONG row — which for a
    /// delete button means destroying the wrong record. `key` is a stable
    /// identity (a name/id) the app resolves instead; a key that no longer
    /// exists is a no-op the app can report. (Found in the M4a review.)
    Table {
        columns: Vec<String>,
        rows: Vec<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        row_action: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        row_buttons: Vec<RowButton>,
        /// Stable identity per row, parallel to `rows`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        row_keys: Vec<String>,
        /// Column indices whose cells hold epoch milliseconds. The DESKTOP
        /// formats them in the owner's local timezone — the same division of
        /// labour as `date_time` (D32): an app never guesses a timezone.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        time_columns: Vec<usize>,
    },
    /// A group whose submit emits `action` carrying every descendant field.
    /// `horizontal` lays the controls out in a wrapping row instead of a
    /// column — for filter bars and other short control sets that shouldn't
    /// each take a full line.
    Form {
        action: String,
        children: Vec<Component>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        horizontal: bool,
    },
    Alert {
        level: AlertLevel,
        text: String,
    },
    Spinner {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    /// An append-only stream (run logs). `id` is required — `AppendLog` targets
    /// it by `component_id`. `lines` is the initial buffer.
    Log {
        id: String,
        #[serde(default)]
        lines: Vec<String>,
    },
    /// A labeled on/off switch. Inside a form it submits as `"true"`/`"false"`
    /// under `id`; `action` (optional) fires immediately on change with
    /// `{value: bool}` for settings that take effect at once.
    Toggle {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        label: String,
        #[serde(default)]
        value: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        action: Option<String>,
    },
    /// Pick when a recurring job first runs, **for a given cadence** — the
    /// input a schedule actually needs (M4c follow-up: the plain
    /// date/time picker "isn't good for general use").
    ///
    /// "Every day at 02:00" should not require picking a date, so the DESKTOP
    /// renders only what the cadence needs (minutes past the hour / a time / a
    /// weekday + time) and computes the epoch-ms anchor from it. Same division
    /// of labour as `date_time` (D32): the browser owns the calendar, the app
    /// receives an instant. Submits as epoch ms under `id`.
    ScheduleAt {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        label: String,
        /// One of the app's cadence labels; the desktop matches on the words
        /// "hour"/"week" and falls back to a daily-style time picker.
        cadence: String,
        /// Current anchor, if editing an existing schedule.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value_ms: Option<u64>,
    },
    /// A labeled dropdown; submits with the form under `id` (M4a review:
    /// pick a playbook/target instead of typing it).
    Select {
        /// Emit this action the moment the choice changes (not on submit), so a
        /// form can re-render around it — the schedule form swaps its time
        /// input when the cadence changes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        action: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        label: String,
        options: Vec<String>,
        #[serde(default)]
        value: String,
    },
    /// One row of mutually-exclusive filter buttons, the active option
    /// highlighted (D42 — Browse's All | Movies | TV). Clicking an option
    /// fires `action` with `{value: <option>}` immediately; unlike Select
    /// it never participates in a form submit.
    Segmented {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        action: String,
        options: Vec<String>,
        value: String,
    },
    /// A text input with datalist suggestions (D42): type-ahead over option
    /// sets too large for a Select. Emits `action` debounced as the user
    /// types; suggestions are hints, not a constraint — any typed text
    /// arrives at the app. Empty `options` makes it a plain live search box.
    ///
    /// **Chip mode** (D44): when `remove_action` is set, the combo is a
    /// multi-select — `chips` render as ×-removable pills, and instead of
    /// live emits, `action` fires once per committed value (Enter, or
    /// picking a suggestion), after which the input clears for the next
    /// one. `remove_action` fires with `{value: <chip>}`.
    Combo {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        label: String,
        action: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        options: Vec<String>,
        #[serde(default)]
        value: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        placeholder: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        chips: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        remove_action: Option<String>,
    },
    /// A file (or whole-folder) picker on the VIEWER's machine, for apps that
    /// need to ingest local files. Selecting fires `action` with
    /// `{files: [{name, path, content}]}` — `name` is the basename, `path` the
    /// path relative to the chosen folder, `content` the file's text. The
    /// desktop enforces the size/count caps and filters by `accept`, so an
    /// app never has to trust the browser side of this.
    ///
    /// Text only by design: this exists for config/playbook-shaped files, not
    /// binary upload (a Mode A app is the right home for that).
    FilePicker {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        label: String,
        /// Fired with the read files (no separate submit).
        action: String,
        /// Pick a whole directory rather than individual files.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        directory: bool,
        /// Extension filter, e.g. `".yml,.yaml"` — an `<input accept>` list.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        accept: Option<String>,
    },
    /// A local date+time picker that submits **epoch milliseconds**, so the
    /// browser's timezone knowledge crosses the wire as an unambiguous
    /// instant and no server component has to know about timezones or DST
    /// (M4c/D32). Rendered in the viewer's local time.
    DateTime {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        label: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value_ms: Option<u64>,
    },
    /// A labeled multi-line editor (playbook YAML etc.); submits with the
    /// form under `id`.
    TextArea {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        label: String,
        #[serde(default)]
        value: String,
        /// D61: what the text IS (`hcl` | `yaml` | `json`). Set, the desktop
        /// renders a real code editor (highlighting, line numbers); absent,
        /// the plain textarea renders exactly as before.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        language: Option<String>,
    },
    /// A tab strip: one child pane per label, switched CLIENT-side (a
    /// background pane keeps receiving `AppendLog` growth without a
    /// round-trip). `id` keys the active-tab state across re-pushes;
    /// `action` (optional) notifies the app of switches with `{tab: index}`.
    /// A small line graph of a recent series — the shape you read at a glance
    /// to see whether a spike just happened (M8). Points are oldest-first and
    /// already in display units; `max` fixes the vertical scale so a 0–100%
    /// chart does not silently rescale itself into looking alarming.
    Chart {
        label: String,
        points: Vec<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max: Option<f64>,
        /// Appended to the current value in the caption ("42%", "1.2 GiB").
        #[serde(default, skip_serializing_if = "String::is_empty")]
        unit: String,
    },
    Tabs {
        id: String,
        labels: Vec<String>,
        children: Vec<Component>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        action: Option<String>,
        /// Ask the desktop to show this tab. Honoured only when it CHANGES, so
        /// a routine re-push never yanks the owner off the tab they chose — but
        /// an app that has something specific to show (a notification's
        /// "Show me" landing on a failed run's log) can put them on it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        active: Option<usize>,
    },
    /// An inline image (D38 — the Media app is the consumer that earned it,
    /// per the D10 "components join when needed" policy). `src` is a
    /// SAME-ORIGIN path — an app-asset route or a `data:` URI — never a
    /// third-party hotlink, so rendering a library never beacons an outside
    /// CDN. The desktop refuses other origins.
    Image {
        src: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        alt: Option<String>,
    },
    /// A wrapping grid of poster cards (D38). Tapping a card fires `action`
    /// with `{key: card.key}`. Card images follow the same same-origin rule
    /// as `Image`.
    CardGrid {
        action: String,
        cards: Vec<Card>,
    },
    /// A button-styled OUTBOUND link (D58 — "Play on Plex"). Unlike
    /// `Button` it emits no event: the desktop renders an anchor
    /// (`target="_blank" rel="noreferrer"`) because a server round-trip
    /// can't open a browser tab. `https://` only — the desktop refuses
    /// other schemes, same posture as the D49 linkifier.
    Link {
        label: String,
        url: String,
    },
    /// Boxes the viewer can drag and resize (D248 — the monitoring map).
    /// Positions are pixels in the picture. Releasing a box fires `action`
    /// with `{id, x, y, w, h}`. pvosd does not interpret this; only the
    /// desktop draws it.
    Diagram {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        action: String,
        nodes: Vec<DiagramNode>,
        edges: Vec<DiagramEdge>,
        /// Redundant dependencies. The arrow points at the group, and the
        /// label says how many of them must be down before the service is.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        clusters: Vec<DiagramCluster>,
    },
    /// D286 — one pane of a file manager. The app sends the listing and the
    /// commands; the desktop keeps the selection, sort and name filter, and
    /// reports a command with the names that were selected. pvosd does not
    /// interpret this; only the desktop draws it.
    FilePane {
        id: String,
        place_id: String,
        places: Vec<FilePlace>,
        path: String,
        crumbs: Vec<FileCrumb>,
        entries: Vec<FileEntry>,
        commands: Vec<FileCommand>,
        /// Every event from this pane: `{op, pane, keys, …}`.
        action: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        status: String,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        status_bad: bool,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        busy: bool,
        /// A text preview of the opened file, under the list.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        preview: String,
        /// When set on the left pane, the desktop asks once, then sends
        /// `replace` or `replace_no`. `confirm_id` changes for each question.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        confirm: String,
        #[serde(default, skip_serializing_if = "is_zero")]
        confirm_id: u64,
    },
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// A service sitting inside the server it runs on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiagramChip {
    pub id: String,
    pub label: String,
}

/// One box on a [`Component::Diagram`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiagramNode {
    pub id: String,
    pub label: String,
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    /// The box this picture is about. Drawn with a stronger border.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub focus: bool,
    /// `runs` or `presents` on the little split box. Empty on a server or a service.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
    /// Services drawn inside this server. An arrow may point at a chip id.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chips: Vec<DiagramChip>,
}

/// A line between two [`DiagramNode`] ids. The arrow points at `to`:
/// `from` depends on `to`. `kind` is `runs` (blue), `presents` (green),
/// or `dns` (the server depends on DNS).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiagramEdge {
    pub from: String,
    pub to: String,
    pub kind: String,
}

/// A group of dependency boxes. One of them staying up keeps the service up
/// until `label`'s count have failed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiagramCluster {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub nodes: Vec<String>,
}

/// A place in a [`Component::FilePane`]'s menu.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FilePlace {
    pub id: String,
    pub label: String,
}

/// One step of the path shown above a file list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileCrumb {
    pub label: String,
    pub path: String,
}

/// One row of a [`Component::FilePane`]. `kind` is `dir`, `file`, `link`
/// or `other`. `key` is the name, unique in that folder.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileEntry {
    pub key: String,
    pub name: String,
    pub kind: String,
    pub size: u64,
    pub mtime_ms: u64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hidden: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

/// A command the desktop draws on a [`Component::FilePane`]. `key` is a
/// `KeyboardEvent.key` (`F5`, `Backspace`). `prompt` asks for a name first;
/// `confirm` asks before the event. The event is the pane's `action` with
/// `{op, pane, keys}` plus `name` when a prompt was answered.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileCommand {
    pub op: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub danger: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub needs_selection: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm: Option<String>,
}

/// One `CardGrid` cell.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Card {
    /// Stable identity, echoed in the tap event (same contract as
    /// `Table::row_keys`).
    pub key: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub subtitle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

/// A per-row table button (M4a). `danger` renders red; `confirm`, when set,
/// makes the desktop show a confirm dialog with that text before emitting.
/// The desktop appends the row's key to the confirm text when `row_keys` is
/// present, so a destructive prompt always names what it will act on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RowButton {
    pub label: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub danger: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertLevel {
    Info,
    Warn,
    Error,
    Success,
}

/// A full surface view-model: the root component the desktop renders (doc 08
/// §4.2). Diffed on re-push; the desktop reconciles rather than reloads.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ViewModel {
    pub root: Component,
    /// D52: the action that returns ONE level up from this view (what
    /// the in-app back/✕ button fires). The desktop maps browser/mouse
    /// back onto it; absent = this view is top-level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub back: Option<String>,
}
