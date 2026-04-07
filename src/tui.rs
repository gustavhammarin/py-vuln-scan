use cvss::v3::Base;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Cell, Paragraph, Row, Table, TableState, Wrap},
    Frame,
};

use crate::schemas::OsvVuln;

pub struct App {
    pub entries: Vec<OsvVuln>,
    pub state: TableState,
}

impl App {
    pub fn new(entries: Vec<OsvVuln>) -> Self {
        let mut state = TableState::default();
        if !entries.is_empty() { state.select(Some(0)); }
        Self { entries, state }
    }

    pub fn next(&mut self) {
        let i = self.state.selected().map(|i| (i + 1) % self.entries.len()).unwrap_or(0);
        self.state.select(Some(i));
    }

    pub fn prev(&mut self) {
        let len = self.entries.len();
        let i = self.state.selected().map(|i| if i == 0 { len - 1 } else { i - 1 }).unwrap_or(0);
        self.state.select(Some(i));
    }
}

const LBL: Style = Style::new().fg(Color::DarkGray).add_modifier(Modifier::BOLD);

pub fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Fill(1)])
        .split(f.area());

    // ── Table ───────────────────────────────────────────────
    let header = Row::new(vec!["ID", "PACKAGE", "SEVERITY", "PUBLISHED"])
        .style(Style::new().fg(Color::DarkGray).add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = app.entries.iter().map(|e| {
        let (label, score) = get_severity(e);
        let sev_color = sev_color(label);
        let sev_text = if score > 0.0 { format!("{} ({:.1})", label, score) } else { label.to_string() };

        Row::new(vec![
            Cell::from(e.id.as_str()),
            Cell::from(get_package(e)),
            Cell::from(sev_text).style(Style::new().fg(sev_color)),
            Cell::from(fmt_date(e.published.as_deref())),
        ])
    }).collect();

    let table = Table::new(rows, [
        Constraint::Length(28),
        Constraint::Fill(1),
        Constraint::Length(16),
        Constraint::Length(12),
    ])
    .header(header)
    .block(Block::bordered().title(" vulnerabilities "))
    .row_highlight_style(Style::new().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
    .highlight_symbol("▶ ");

    f.render_stateful_widget(table, chunks[0], &mut app.state);

    // ── Detail panel ────────────────────────────────────────
    let Some(i) = app.state.selected() else { return };
    let Some(entry) = app.entries.get(i) else { return };

    let (label, score) = get_severity(entry);
    let fixed = get_fixed_version(entry).unwrap_or_else(|| "—".to_string());
    let paket = format!("{} ({})", get_package(entry), get_ecosystem(entry));
    let sev_text = if score > 0.0 { format!("{} ({:.1})", label, score) } else { label.to_string() };

    let mut lines: Vec<Line> = vec![
        kv("ID:       ", &entry.id),
        kv("Package:  ", &paket),
        Line::from(vec![
            Span::styled("Severity: ", LBL),
            Span::styled(sev_text, Style::new().fg(sev_color(label)).add_modifier(Modifier::BOLD)),
        ]),
        kv("Fixed:    ", &fixed),
        kv("Published:", entry.published.as_deref().unwrap_or("—")),
        kv("Advisory: ", get_advisory_url(entry).unwrap_or("—")),
        Line::raw(""),
    ];

    let summary = entry.summary.as_deref().unwrap_or("");
    if !summary.is_empty() {
        lines.push(Line::styled("Summary:", LBL));
        lines.push(Line::raw(summary));
        lines.push(Line::raw(""));
    }

    let details = entry.details.as_deref().unwrap_or("");
    if !details.is_empty() && details != summary {
        lines.push(Line::styled("Details:", LBL));
        for line in details.lines() {
            lines.push(Line::raw(line.to_string()));
        }
    }

    let info = Paragraph::new(lines)
        .block(Block::bordered().title(" details "))
        .wrap(Wrap { trim: true });

    f.render_widget(info, chunks[1]);
}

fn kv<'a>(label: &'a str, value: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(label, LBL),
        Span::raw(value),
    ])
}

fn sev_color(label: &str) -> Color {
    match label {
        "CRITICAL" => Color::Red,
        "HIGH"     => Color::Yellow,
        "MEDIUM"   => Color::Cyan,
        "LOW"      => Color::Green,
        _          => Color::DarkGray,
    }
}

fn fmt_date(s: Option<&str>) -> &str {
    s.and_then(|d| d.get(..10)).unwrap_or("—")
}

fn get_advisory_url(entry: &OsvVuln) -> Option<&str> {
    let refs = entry.references.as_ref()?;
    refs.iter()
        .find(|r| r.r#type == "ADVISORY")
        .or_else(|| refs.first())
        .map(|r| r.url.as_str())
}

fn get_fixed_version(entry: &OsvVuln) -> Option<String> {
    let versions: Vec<&str> = entry.affected.as_ref()?
        .iter()
        .flat_map(|a| a.ranges.iter().flatten())
        .flat_map(|r| r.events.iter().flatten())
        .filter_map(|e| e.fixed.as_deref())
        .collect();

    if versions.is_empty() { None } else { Some(versions.join(", ")) }
}

fn get_ecosystem(entry: &OsvVuln) -> &str {
    entry.affected.as_ref()
        .and_then(|a| a.first())
        .and_then(|a| a.package.as_ref())
        .map(|p| p.ecosystem.as_str())
        .unwrap_or("—")
}

pub fn get_package(entry: &OsvVuln) -> &str {
    entry.affected.as_ref()
        .and_then(|a| a.first())
        .and_then(|a| a.package.as_ref())
        .map(|p| p.name.as_str())
        .unwrap_or("—")
}

fn get_severity(entry: &OsvVuln) -> (&'static str, f64) {
    let score_str = entry.severity.as_ref()
        .and_then(|s| s.first())
        .map(|s| s.score.as_str())
        .unwrap_or("");

    let val: f64 = score_str
        .parse::<Base>()
        .map(|b| b.score().value())
        .unwrap_or(0.0);

    let label = match val {
        v if v >= 9.0 => "CRITICAL",
        v if v >= 7.0 => "HIGH",
        v if v >= 4.0 => "MEDIUM",
        v if v > 0.0  => "LOW",
        _             => "—",
    };

    (label, val)
}
