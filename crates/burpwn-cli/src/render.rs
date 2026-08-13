//! Output rendering — the one place that decides what a human at a terminal
//! sees and what a *program* (an AI agent, a pipe, a `--json` consumer) gets.
//!
//! # The rule
//!
//! Decoration exists for humans. Column headers, alignment padding, summary
//! footers, colour: all of it is comfort a person reads and a program pays for
//! in tokens, one token at a time, on every turn it keeps the output in context.
//! So the decision here is not "colour or no colour", it is **structure**:
//!
//! - [`Mode::Pretty`] — stdout is a terminal. Headers, column widths measured
//!   ON THE DATA, semantic colour, a footer summarising the listing, ellipsis
//!   truncation when a row would wrap.
//! - [`Mode::Terse`] — stdout is a pipe, a file, or an agent's capture buffer.
//!   One record per line, TAB-separated, **no** header, **no** footer, **no**
//!   padding, **no** truncation: the data, whole, and nothing else. It stays
//!   parsable — `awk` splits on the tab by default, `cut -f` uses it as its
//!   default delimiter, and an empty cell is emitted as `-` so field positions
//!   hold for `awk '{print $2}'`.
//! - [`Mode::Json`] — `--json`. Nothing but the envelope reaches stdout; the
//!   MCP layer parses the last non-empty stdout line, so a single stray line of
//!   prose there is a protocol break, not a cosmetic issue.
//!
//! Every [`Table`] renders through the same pure function
//! ([`Table::render`]), so what a mode produces is unit-testable without a
//! terminal, a subprocess or a snapshot file.
//!
//! # Colour
//!
//! Colour is decided once, at startup, from the environment:
//! `NO_COLOR` (present with ANY value) wins over everything and disables it;
//! `CLICOLOR_FORCE` (present, not `0`) enables it even when stdout is not a
//! terminal. Otherwise it follows the TTY. Note that `CLICOLOR_FORCE` colours
//! terse output but does not restore its structure — the caller asked for
//! escape codes, not for headers.

use std::io::IsTerminal;

use anstyle::{AnsiColor, Color, Style};

/// Fallback terminal width when neither `COLUMNS` nor the `ioctl` answers.
const DEFAULT_WIDTH: usize = 100;

/// Never assume a terminal narrower than this: below it, truncation would eat
/// the data instead of the padding.
const MIN_WIDTH: usize = 40;

/// A truncated column is never squeezed below this (ellipsis included).
const MIN_TRUNCATED_COL: usize = 12;

/// The gap between two columns in [`Mode::Pretty`].
const GAP: usize = 2;

/// The left margin of a pretty listing.
const INDENT: usize = 2;

/// What the process is writing to, and therefore how much decoration is
/// justified. Decided once in [`Render::detect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `--json`: the envelope, alone, on stdout.
    Json,
    /// stdout is a terminal: aligned columns, headers, colour, footers.
    Pretty,
    /// stdout is a pipe/file/capture: TAB-separated records, nothing else.
    Terse,
}

/// The rendering decision for this process: mode, colour, terminal width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Render {
    mode: Mode,
    color: bool,
    width: usize,
}

impl Render {
    /// Decide the mode from the `--json` flag and the environment. Called once,
    /// at dispatch; everything downstream reads the decision rather than
    /// re-testing `is_terminal()` (which would let two parts of one command
    /// disagree if stdout were replaced mid-run).
    pub fn detect(json: bool) -> Self {
        if json {
            return Self::json();
        }
        let tty = std::io::stdout().is_terminal();
        let color = color_enabled(tty);
        if tty {
            Self {
                mode: Mode::Pretty,
                color,
                width: terminal_width(),
            }
        } else {
            Self {
                mode: Mode::Terse,
                color,
                width: 0,
            }
        }
    }

    /// The `--json` renderer.
    pub fn json() -> Self {
        Self {
            mode: Mode::Json,
            color: false,
            width: 0,
        }
    }

    /// A terminal renderer of an explicit width, colour on (tests, `COLUMNS`).
    pub fn pretty(width: usize) -> Self {
        Self {
            mode: Mode::Pretty,
            color: true,
            width: width.max(MIN_WIDTH),
        }
    }

    /// The machine renderer: TAB-separated records, no decoration.
    pub fn terse() -> Self {
        Self {
            mode: Mode::Terse,
            color: false,
            width: 0,
        }
    }

    /// Same mode, colour forced off (what `NO_COLOR` produces).
    pub fn without_color(self) -> Self {
        Self {
            color: false,
            ..self
        }
    }

    /// The active mode.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Whether the envelope is the only thing allowed on stdout.
    pub fn is_json(&self) -> bool {
        self.mode == Mode::Json
    }

    /// Whether decoration (headers, padding, footers) is wanted.
    pub fn is_pretty(&self) -> bool {
        self.mode == Mode::Pretty
    }

    /// Whether escape codes may be emitted.
    pub fn color(&self) -> bool {
        self.color
    }

    /// The usable terminal width (0 outside [`Mode::Pretty`]).
    pub fn width(&self) -> usize {
        self.width
    }

    /// Wrap `text` in `style` when colour is on, else hand it back untouched.
    pub fn paint(&self, text: &str, style: Style) -> String {
        if !self.color || style.is_plain() || text.is_empty() {
            return text.to_string();
        }
        format!("{}{text}{}", style.render(), style.render_reset())
    }

    /// A line of commentary (a hint, a "now do this" follow-up) that only a
    /// human benefits from: `None` in every non-pretty mode, so callers can
    /// `if let Some(l) = r.aside(...)` instead of branching on the mode.
    pub fn aside(&self, text: impl AsRef<str>) -> Option<String> {
        self.is_pretty()
            .then(|| format!("{}{}", " ".repeat(INDENT), text.as_ref()))
    }
}

/// `NO_COLOR` beats `CLICOLOR_FORCE` beats the TTY. Presence is what counts for
/// `NO_COLOR` (any value, including empty), per the no-color.org convention.
fn color_enabled(tty: bool) -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    match std::env::var("CLICOLOR_FORCE") {
        Ok(v) if v != "0" => return true,
        _ => {}
    }
    tty
}

/// The terminal width: `COLUMNS` first (it is what a user overrides and what a
/// test sets), then `TIOCGWINSZ` on stdout, then a sane default.
fn terminal_width() -> usize {
    if let Some(w) = std::env::var("COLUMNS").ok().and_then(|v| v.parse().ok()) {
        return usize::max(w, MIN_WIDTH);
    }
    // SAFETY: `winsize` is a plain POD struct and fd 1 is valid for the ioctl;
    // a failure is reported by the return code and leaves `ws` zeroed.
    let ws: libc::winsize = unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) != 0 {
            ws.ws_col = 0;
        }
        ws
    };
    if ws.ws_col > 0 {
        usize::max(ws.ws_col as usize, MIN_WIDTH)
    } else {
        DEFAULT_WIDTH
    }
}

// --- semantic colour --------------------------------------------------------

/// The palette. Meaning first: a colour here says what a value IS, never
/// decorates it. Everything is an ANSI base colour so it inherits the user's
/// terminal theme instead of fighting it.
pub mod palette {
    use super::{AnsiColor, Color, Style};

    const fn fg(c: AnsiColor) -> Style {
        Style::new().fg_color(Some(Color::Ansi(c)))
    }

    /// Column headers.
    pub const HEADER: Style = Style::new().dimmed();
    /// The footer summarising a listing.
    pub const FOOTER: Style = Style::new().dimmed();
    /// A label in a key/value block.
    pub const LABEL: Style = Style::new();
    /// Something absent, disabled, or not applicable.
    pub const MUTED: Style = Style::new().dimmed();
    /// A good outcome (`yes`, `ok`, 2xx).
    pub const GOOD: Style = fg(AnsiColor::Green);
    /// Something worth a second look (3xx, degraded, a `--redact`-less export).
    pub const WARN: Style = fg(AnsiColor::Yellow);
    /// A client-side refusal (4xx) — interesting, not broken.
    pub const NOTICE: Style = fg(AnsiColor::Magenta);
    /// A failure (`NO`, FAIL, 5xx).
    pub const BAD: Style = fg(AnsiColor::Red);
    /// An identifier the user will type back (ids, names).
    pub const IDENT: Style = fg(AnsiColor::Cyan);
    /// The heading of an error block.
    pub const ERROR_HEAD: Style = fg(AnsiColor::Red).bold();

    /// HTTP status classes, which is the one colouring every pentester already
    /// reads without thinking: 2xx fine, 3xx moved, 4xx refused, 5xx broken.
    pub fn status(code: u16) -> Style {
        match code {
            100..=199 => MUTED,
            200..=299 => GOOD,
            300..=399 => WARN,
            400..=499 => NOTICE,
            _ => BAD,
        }
    }

    /// A yes/no preflight answer.
    pub fn yes_no(ok: bool) -> Style {
        if ok {
            GOOD
        } else {
            BAD
        }
    }

    /// A fuzz anomaly score in `0.0..=1.0`: the gradient is the whole point of
    /// the Intruder table, since the eye should land on the outlier before the
    /// numbers are read.
    pub fn anomaly(score: f64) -> Style {
        if score >= 0.66 {
            BAD
        } else if score >= 0.33 {
            WARN
        } else if score > 0.0 {
            NOTICE
        } else {
            MUTED
        }
    }

    /// A stored tag colour (the `tags.color` column, which until now nothing
    /// ever looked at). Unknown names fall back to plain.
    pub fn tag(color: Option<&str>) -> Style {
        let Some(name) = color else {
            return Style::new();
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "red" => fg(AnsiColor::Red),
            "green" => fg(AnsiColor::Green),
            "yellow" | "orange" => fg(AnsiColor::Yellow),
            "blue" => fg(AnsiColor::Blue),
            "magenta" | "purple" | "pink" => fg(AnsiColor::Magenta),
            "cyan" | "teal" => fg(AnsiColor::Cyan),
            "grey" | "gray" => Style::new().dimmed(),
            "white" => fg(AnsiColor::White),
            "black" => fg(AnsiColor::Black),
            _ => Style::new(),
        }
    }
}

// --- tables -----------------------------------------------------------------

/// Which edge a column's padding goes on. Only meaningful in [`Mode::Pretty`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    /// Text: pad on the right.
    Left,
    /// Numbers: pad on the left, so digits line up.
    Right,
}

/// A column: its header (empty for a key/value block), alignment, and whether
/// it may be shortened when the row does not fit the terminal.
#[derive(Debug, Clone)]
pub struct Column {
    header: String,
    align: Align,
    truncate: bool,
}

impl Column {
    /// A left-aligned text column.
    pub fn left(header: impl Into<String>) -> Self {
        Self {
            header: header.into(),
            align: Align::Left,
            truncate: false,
        }
    }

    /// A right-aligned column, for numbers.
    pub fn right(header: impl Into<String>) -> Self {
        Self {
            header: header.into(),
            align: Align::Right,
            truncate: false,
        }
    }

    /// Mark this column as the one that gives ground when the row is too wide
    /// (URLs, descriptions, commands). Never truncated in terse mode.
    pub fn truncatable(mut self) -> Self {
        self.truncate = true;
        self
    }
}

/// One rendered value plus the meaning-colour it carries.
#[derive(Debug, Clone)]
pub struct Cell {
    text: String,
    style: Style,
}

impl Cell {
    /// A plain value.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            style: Style::new(),
        }
    }

    /// A value carrying a semantic colour (see [`palette`]).
    pub fn styled(text: impl Into<String>, style: Style) -> Self {
        Self {
            text: text.into(),
            style,
        }
    }

    /// The unstyled text — what terse mode emits and what tests assert on.
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl From<&str> for Cell {
    fn from(s: &str) -> Self {
        Cell::new(s)
    }
}

impl From<String> for Cell {
    fn from(s: String) -> Self {
        Cell::new(s)
    }
}

/// A listing: columns measured on the data, rows, and an optional footer that
/// only a human ever sees.
#[derive(Debug, Clone)]
pub struct Table {
    columns: Vec<Column>,
    rows: Vec<Vec<Cell>>,
    footer: Option<String>,
}

impl Table {
    /// A table with these columns.
    pub fn new(columns: Vec<Column>) -> Self {
        Self {
            columns,
            rows: Vec::new(),
            footer: None,
        }
    }

    /// Append a row. Extra cells beyond the column count are ignored, missing
    /// ones render empty — a listing must never panic on its own data.
    pub fn row(&mut self, cells: Vec<Cell>) -> &mut Self {
        self.rows.push(cells);
        self
    }

    /// The one-line summary under the table (`4 flows · workspace default`).
    /// Pretty mode only: in terse mode it would be a line that parses as a
    /// record but is not one.
    pub fn footer(&mut self, text: impl Into<String>) -> &mut Self {
        self.footer = Some(text.into());
        self
    }

    /// How many rows the table holds.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the table has no rows.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Render to a string (no trailing newline). Pure: the same inputs give the
    /// same output on any machine, with or without a terminal.
    pub fn render(&self, r: &Render) -> String {
        match r.mode() {
            Mode::Terse | Mode::Json => self.render_terse(),
            Mode::Pretty => self.render_pretty(r),
        }
    }

    /// TAB-separated records: the data whole, one per line. An empty value
    /// becomes `-` so `awk '{print $3}'` keeps pointing at the same field.
    fn render_terse(&self) -> String {
        let mut out = String::new();
        for row in &self.rows {
            let line: Vec<&str> = (0..self.columns.len())
                .map(|i| match row.get(i).map(Cell::text).unwrap_or("") {
                    "" => "-",
                    s => s,
                })
                .collect();
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&line.join("\t"));
        }
        out
    }

    fn render_pretty(&self, r: &Render) -> String {
        let widths = self.fitted_widths(r.width());
        let has_header = self.columns.iter().any(|c| !c.header.is_empty());
        let mut lines: Vec<String> = Vec::with_capacity(self.rows.len() + 3);

        if has_header {
            let cells: Vec<Cell> = self
                .columns
                .iter()
                .map(|c| Cell::new(c.header.to_uppercase()))
                .collect();
            lines.push(self.render_row(r, &cells, &widths, Some(palette::HEADER)));
        }
        for row in &self.rows {
            lines.push(self.render_row(r, row, &widths, None));
        }
        if let Some(f) = &self.footer {
            lines.push(String::new());
            lines.push(format!(
                "{}{}",
                " ".repeat(INDENT),
                r.paint(f, palette::FOOTER)
            ));
        }
        lines.join("\n")
    }

    /// One padded, coloured line. `force` overrides every cell's own style (the
    /// header row); trailing padding on the last column is dropped, because
    /// invisible spaces at end of line are exactly the thing that survives a
    /// copy/paste and breaks a diff.
    fn render_row(
        &self,
        r: &Render,
        row: &[Cell],
        widths: &[usize],
        force: Option<Style>,
    ) -> String {
        let mut line = " ".repeat(INDENT);
        let last = self.columns.len().saturating_sub(1);
        for (i, col) in self.columns.iter().enumerate() {
            let empty = Cell::new("");
            let cell = row.get(i).unwrap_or(&empty);
            let text = truncate(cell.text(), widths[i]);
            let pad = widths[i].saturating_sub(display_width(&text));
            let painted = r.paint(&text, force.unwrap_or(cell.style));
            match col.align {
                Align::Right => {
                    line.push_str(&" ".repeat(pad));
                    line.push_str(&painted);
                }
                Align::Left => {
                    line.push_str(&painted);
                    if i != last {
                        line.push_str(&" ".repeat(pad));
                    }
                }
            }
            if i != last {
                line.push_str(&" ".repeat(GAP));
            }
        }
        // A right-aligned last column can still leave nothing behind it.
        line.trim_end().to_string()
    }

    /// Column widths measured on the data (header included), then shrunk —
    /// widest truncatable column first — until the row fits the terminal.
    fn fitted_widths(&self, term_width: usize) -> Vec<usize> {
        let mut widths: Vec<usize> = self
            .columns
            .iter()
            .map(|c| display_width(&c.header))
            .collect();
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate().take(widths.len()) {
                widths[i] = widths[i].max(display_width(cell.text()));
            }
        }
        if term_width == 0 {
            return widths;
        }
        let fixed = INDENT + GAP * self.columns.len().saturating_sub(1);
        loop {
            let total: usize = fixed + widths.iter().sum::<usize>();
            if total <= term_width {
                return widths;
            }
            // Shrink the widest column that is allowed to give ground.
            let victim = self
                .columns
                .iter()
                .enumerate()
                .filter(|(i, c)| c.truncate && widths[*i] > MIN_TRUNCATED_COL)
                .max_by_key(|(i, _)| widths[*i])
                .map(|(i, _)| i);
            let Some(i) = victim else {
                // Nothing left to give: a too-narrow terminal wraps rather than
                // losing data.
                return widths;
            };
            let excess = total - term_width;
            widths[i] = widths[i].saturating_sub(excess).max(MIN_TRUNCATED_COL);
        }
    }
}

/// Shorten to `max` display columns, marking the cut with `…` (which is itself
/// one column wide). Never called in terse mode.
fn truncate(text: &str, max: usize) -> String {
    if max == 0 || display_width(text) <= max {
        return text.to_string();
    }
    let keep = max.saturating_sub(1);
    let mut out: String = text.chars().take(keep).collect();
    out.push('…');
    out
}

/// Display width in terminal columns. Control characters take none; everything
/// else counts as one. burpwn's own output is ASCII plus a handful of symbols
/// (`…`, `⚠`, `·`), so this is exact for it and merely approximate for a URL
/// carrying wide CJK — which mis-pads a column but never loses data.
fn display_width(s: &str) -> usize {
    s.chars().filter(|c| !c.is_control()).count()
}

// --- key/value blocks -------------------------------------------------------

/// A `label  value  detail` block (what `doctor` prints): a [`Table`] with no
/// headers, so it aligns on the data and degrades to TAB-separated records
/// exactly like every other listing.
pub fn kv_table() -> Table {
    Table::new(vec![
        Column::left(""),
        Column::left(""),
        Column::left("").truncatable(),
    ])
}

/// A `label  value` block, for the reports that have no third field — a third
/// column of `-` is a column of nothing, charged per line.
pub fn kv_pair() -> Table {
    Table::new(vec![Column::left(""), Column::left("").truncatable()])
}

// --- error block ------------------------------------------------------------

/// Colour the rendered diagnostic block for a human at a terminal.
///
/// The plain text is the contract — the README documents it and
/// `burpwn-error`'s own test asserts it verbatim — so this only ever ADDS
/// escape codes, and only when stderr is a terminal. Piped, redirected or
/// captured by an agent, the block is byte-for-byte what it always was.
pub fn error_block(text: &str) -> String {
    if !std::io::stderr().is_terminal() || !color_enabled(true) {
        return text.to_string();
    }
    let head = palette::ERROR_HEAD;
    let label = palette::MUTED;
    text.lines()
        .map(|line| {
            if let Some(rest) = line.strip_prefix("error ") {
                format!("{}error{} {rest}", head.render(), head.render_reset())
            } else if let Some((lhs, rhs)) = split_label(line) {
                format!("{}{lhs}{}{rhs}", label.render(), label.render_reset())
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Split `  cause : text` into its label part (`  cause : `) and the rest.
fn split_label(line: &str) -> Option<(&str, &str)> {
    if !line.starts_with("  ") {
        return None;
    }
    let idx = line.find(": ")?;
    // Only a real label: no spaces in the name between the indent and the colon.
    let name = line[2..idx].trim_end();
    if name.is_empty() || name.contains(' ') {
        return None;
    }
    Some(line.split_at(idx + 2))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flows() -> Table {
        let mut t = Table::new(vec![
            Column::right("id"),
            Column::left("proto"),
            Column::left("method"),
            Column::left("url").truncatable(),
            Column::right("status"),
        ]);
        t.row(vec![
            Cell::new("12"),
            Cell::new("https"),
            Cell::new("GET"),
            Cell::new("/v2/users?page=1"),
            Cell::styled("200", palette::status(200)),
        ]);
        t.row(vec![
            Cell::new("13"),
            Cell::new("https"),
            Cell::new("POST"),
            Cell::new("/v2/login"),
            Cell::styled("401", palette::status(401)),
        ]);
        t.footer("2 flows  ·  workspace default");
        t
    }

    // The contract an agent depends on: no header, no footer, no padding, no
    // colour — and the fields still land where `awk` expects them.
    #[test]
    fn terse_is_data_only_and_tab_separated() {
        let text = flows().render(&Render::terse());
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "header or footer leaked: {text:?}");
        assert_eq!(lines[0], "12\thttps\tGET\t/v2/users?page=1\t200");
        assert!(!text.contains("STATUS"));
        assert!(!text.contains("flows  ·"));
        assert!(!text.contains('\u{1b}'));
        assert!(!text.contains("  "), "padding leaked: {text:?}");
        // `awk '{print $5}'` sees the status on every line.
        for line in lines {
            assert_eq!(line.split('\t').count(), 5);
        }
    }

    /// An empty cell would collapse under `awk`'s default field splitting and
    /// silently shift every later column, so it is emitted as `-`.
    #[test]
    fn terse_keeps_empty_fields_positional() {
        let mut t = Table::new(vec![Column::left("a"), Column::left("b")]);
        t.row(vec![Cell::new(""), Cell::new("x")]);
        assert_eq!(t.render(&Render::terse()), "-\tx");
    }

    #[test]
    fn pretty_has_header_footer_and_alignment() {
        let text = flows().render(&Render::pretty(100).without_color());
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].starts_with("  ID  PROTO  METHOD  URL"));
        assert!(lines[0].trim_end().ends_with("STATUS"));
        // The two ids line up, and so do the two statuses.
        let id_col = |l: &str| l.find(|c: char| !c.is_whitespace()).unwrap();
        assert_eq!(id_col(lines[1]), id_col(lines[2]));
        assert_eq!(lines[1].len(), lines[2].len());
        assert_eq!(
            lines.last().unwrap().trim(),
            "2 flows  ·  workspace default"
        );
    }

    /// Widths come from the data, not from a hard-coded `{:>6}`: a longer value
    /// widens its column instead of pushing every later column out of line.
    #[test]
    fn widths_are_measured_on_the_data() {
        let mut t = Table::new(vec![Column::left(""), Column::left("")]);
        t.row(vec![Cell::new("a"), Cell::new("1")]);
        t.row(vec![Cell::new("aaaaaaaa"), Cell::new("2")]);
        let text = t.render(&Render::pretty(100).without_color());
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "  a         1");
        assert_eq!(lines[1], "  aaaaaaaa  2");
    }

    #[test]
    fn a_long_value_is_ellipsised_to_the_terminal_width() {
        let mut t = Table::new(vec![
            Column::right("id"),
            Column::left("url").truncatable(),
            Column::right("status"),
        ]);
        t.row(vec![
            Cell::new("15"),
            Cell::new(format!("/v2/{}", "x".repeat(200))),
            Cell::new("403"),
        ]);
        let pretty = t.render(&Render::pretty(60).without_color());
        for line in pretty.lines() {
            assert!(display_width(line) <= 60, "{line:?}");
        }
        assert!(pretty.contains('…'));
        // …but the pipe gets the whole URL, untruncated.
        let terse = t.render(&Render::terse());
        assert!(terse.contains(&"x".repeat(200)));
        assert!(!terse.contains('…'));
    }

    #[test]
    fn colour_is_pretty_only_and_semantic() {
        let colored = flows().render(&Render::pretty(100));
        assert!(colored.contains('\u{1b}'));
        // 2xx and 4xx do not get the same escape sequence.
        let green = Render::pretty(100).paint("200", palette::status(200));
        let magenta = Render::pretty(100).paint("401", palette::status(401));
        assert_ne!(green, magenta);
        assert!(colored.contains(&green));
        assert!(colored.contains(&magenta));
        // NO_COLOR strips the escapes but keeps the structure.
        let plain = flows().render(&Render::pretty(100).without_color());
        assert!(!plain.contains('\u{1b}'));
        assert!(plain.contains("STATUS"));
    }

    #[test]
    fn no_color_wins_over_clicolor_force() {
        temp_env(
            &[("NO_COLOR", Some("")), ("CLICOLOR_FORCE", Some("1"))],
            || {
                assert!(!color_enabled(true));
            },
        );
        temp_env(&[("NO_COLOR", None), ("CLICOLOR_FORCE", Some("1"))], || {
            assert!(color_enabled(false));
        });
        temp_env(&[("NO_COLOR", None), ("CLICOLOR_FORCE", Some("0"))], || {
            assert!(!color_enabled(false));
            assert!(color_enabled(true));
        });
    }

    #[test]
    fn json_mode_renders_nothing_decorative() {
        // A table rendered in JSON mode is never printed, but if a caller does
        // it anyway it must not invent a header.
        let text = flows().render(&Render::json());
        assert!(!text.contains("STATUS"));
        assert_eq!(text.lines().count(), 2);
    }

    #[test]
    fn asides_are_pretty_only() {
        assert!(Render::terse().aside("try this").is_none());
        assert!(Render::json().aside("try this").is_none());
        assert_eq!(
            Render::pretty(80).aside("try this").as_deref(),
            Some("  try this")
        );
    }

    /// The error block's plain text is asserted verbatim by `burpwn-error` and
    /// documented in the README; styling may only add escapes, never bytes.
    #[test]
    fn error_block_is_untouched_without_a_terminal() {
        let text = "error [BW-SANDBOX-003] boom\n  cause : ip link add burp0\n  exit  : 70";
        // The test process's stderr is not a terminal under `cargo test`.
        assert_eq!(error_block(text), text);
    }

    #[test]
    fn label_split_only_matches_real_labels() {
        assert_eq!(
            split_label("  cause : ip link add burp0 failed"),
            Some(("  cause : ", "ip link add burp0 failed"))
        );
        // A URL in the body of a line is not a label.
        assert_eq!(split_label("  see https://example.com: nope"), None);
        assert_eq!(split_label("no indent : x"), None);
    }

    /// Set env vars for the duration of `f` and put them back afterwards.
    fn temp_env(vars: &[(&str, Option<&str>)], f: impl FnOnce()) {
        let saved: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|(k, _)| (k.to_string(), std::env::var(k).ok()))
            .collect();
        for (k, v) in vars {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        f();
        for (k, v) in saved {
            match v {
                Some(v) => std::env::set_var(&k, v),
                None => std::env::remove_var(&k),
            }
        }
    }
}
