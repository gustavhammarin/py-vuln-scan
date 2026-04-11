use cvss::v3::Base;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Cell, Paragraph, Row, Table, TableState, Wrap},
    Frame,
};

use crate::osv::OsvVuln;

pub struct App {
    pub entries: Vec<OsvVuln>,
    pub state: TableState,
}

impl App {
    pub fn new(entries: Vec<OsvVuln>) -> Self {
        let mut state = TableState::default();
        if !entries.is_empty() {
            state.select(Some(0));
        }
        Self { entries, state }
    }

    pub fn next(&mut self) {
        let i = self
            .state
            .selected()
            .map(|i| (i + 1) % self.entries.len())
            .unwrap_or(0);
        self.state.select(Some(i));
    }

    pub fn prev(&mut self) {
        let len = self.entries.len();
        let i = self
            .state
            .selected()
            .map(|i| if i == 0 { len - 1 } else { i - 1 })
            .unwrap_or(0);
        self.state.select(Some(i));
    }
}

const LBL: Style = Style::new()
    .fg(Color::DarkGray)
    .add_modifier(Modifier::BOLD);

pub fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Fill(1)])
        .split(f.area());

    // ── Table ───────────────────────────────────────────────
    let header = Row::new(vec!["ID", "PACKAGE", "SEVERITY", "PUBLISHED"])
        .style(Style::new().fg(Color::DarkGray).add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = app
        .entries
        .iter()
        .map(|e| {
            let (label, score) = get_severity(e);
            let sev_color = sev_color(label);
            let sev_text = if score > 0.0 {
                format!("{} ({:.1})", label, score)
            } else {
                label.to_string()
            };

            Row::new(vec![
                Cell::from(e.id.as_str()),
                Cell::from(get_package(e)),
                Cell::from(sev_text).style(Style::new().fg(sev_color)),
                Cell::from(fmt_date(e.published.as_deref())),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(28),
            Constraint::Fill(1),
            Constraint::Length(16),
            Constraint::Length(12),
        ],
    )
    .header(header)
    .block(Block::bordered().title(" vulnerabilities "))
    .row_highlight_style(Style::new().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
    .highlight_symbol("▶ ");

    f.render_stateful_widget(table, chunks[0], &mut app.state);

    // ── Detail panel ────────────────────────────────────────
    let Some(i) = app.state.selected() else {
        return;
    };
    let Some(entry) = app.entries.get(i) else {
        return;
    };

    let (label, score) = get_severity(entry);
    let fixed = get_fixed_version(entry).unwrap_or_else(|| "—".to_string());
    let paket = format!("{} ({})", get_package(entry), get_ecosystem(entry));
    let sev_text = if score > 0.0 {
        format!("{} ({:.1})", label, score)
    } else {
        label.to_string()
    };

    let mut lines: Vec<Line> = vec![
        kv("ID:       ", &entry.id),
        kv("Package:  ", &paket),
        Line::from(vec![
            Span::styled("Severity: ", LBL),
            Span::styled(
                sev_text,
                Style::new()
                    .fg(sev_color(label))
                    .add_modifier(Modifier::BOLD),
            ),
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
    Line::from(vec![Span::styled(label, LBL), Span::raw(value)])
}

fn sev_color(label: &str) -> Color {
    match label {
        "CRITICAL" => Color::Red,
        "HIGH" => Color::Yellow,
        "MEDIUM" => Color::Cyan,
        "LOW" => Color::Green,
        _ => Color::DarkGray,
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
    let versions: Vec<&str> = entry
        .affected
        .as_ref()?
        .iter()
        .flat_map(|a| a.ranges.iter().flatten())
        .flat_map(|r| r.events.iter().flatten())
        .filter_map(|e| e.fixed.as_deref())
        .collect();

    if versions.is_empty() {
        None
    } else {
        Some(versions.join(", "))
    }
}

fn get_ecosystem(entry: &OsvVuln) -> &str {
    entry
        .affected
        .as_ref()
        .and_then(|a| a.first())
        .and_then(|a| a.package.as_ref())
        .map(|p| p.ecosystem.as_str())
        .unwrap_or("—")
}

pub fn get_package(entry: &OsvVuln) -> &str {
    entry
        .affected
        .as_ref()
        .and_then(|a| a.first())
        .and_then(|a| a.package.as_ref())
        .map(|p| p.name.as_str())
        .unwrap_or("—")
}

fn get_severity(entry: &OsvVuln) -> (&'static str, f64) {
    let score_str = entry
        .severity
        .as_ref()
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
        v if v > 0.0 => "LOW",
        _ => "—",
    };

    (label, val)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osv::{
        OsvAffected, OsvAffectedPackage, OsvEvent, OsvRange, OsvReference, OsvSeverity, OsvVuln,
    };

    // --- Helpers ------------------------------------------------------------

    fn empty_vuln() -> OsvVuln {
        OsvVuln {
            id: "TEST-001".to_string(),
            schema_version: None,
            modified: None,
            published: None,
            withdrawn: None,
            aliases: None,
            upstream: None,
            related: None,
            summary: None,
            details: None,
            severity: None,
            affected: None,
            references: None,
            credits: None,
            database_specific: None,
        }
    }

    // --- fmt_date -----------------------------------------------------------

    #[test]
    fn fmt_date_extracts_first_ten_chars() {
        assert_eq!(fmt_date(Some("2024-03-15T12:00:00Z")), "2024-03-15");
    }

    #[test]
    fn fmt_date_returns_fallback_for_none() {
        assert_eq!(fmt_date(None), "—");
    }

    #[test]
    fn fmt_date_returns_fallback_for_short_string() {
        assert_eq!(fmt_date(Some("2024")), "—");
    }

    // --- get_severity -------------------------------------------------------

    #[test]
    fn no_severity_returns_dash_and_zero() {
        let (label, score) = get_severity(&empty_vuln());
        assert_eq!(label, "—");
        assert_eq!(score, 0.0);
    }

    #[test]
    fn critical_score_returns_critical_label() {
        let mut vuln = empty_vuln();
        // CVSS:3.1 score 9.8 — network, low complexity, no privileges, no user interaction
        vuln.severity = Some(vec![OsvSeverity {
            r#type: "CVSS_V3".to_string(),
            score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
        }]);
        let (label, score) = get_severity(&vuln);
        assert_eq!(label, "CRITICAL");
        assert!(score >= 9.0);
    }

    #[test]
    fn medium_score_returns_medium_label() {
        let mut vuln = empty_vuln();
        // CVSS:3.1 score ~5.3
        vuln.severity = Some(vec![OsvSeverity {
            r#type: "CVSS_V3".to_string(),
            score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N".to_string(),
        }]);
        let (label, score) = get_severity(&vuln);
        assert_eq!(label, "MEDIUM");
        assert!(score >= 4.0 && score < 7.0);
    }

    // --- get_package --------------------------------------------------------

    #[test]
    fn get_package_returns_name_from_affected() {
        let mut vuln = empty_vuln();
        vuln.affected = Some(vec![OsvAffected {
            package: Some(OsvAffectedPackage {
                ecosystem: "PyPI".to_string(),
                name: "requests".to_string(),
                purl: None,
            }),
            severity: None,
            ranges: None,
            versions: None,
            ecosystem_specific: None,
            database_specific: None,
        }]);
        assert_eq!(get_package(&vuln), "requests");
    }

    #[test]
    fn get_package_returns_dash_when_no_affected() {
        assert_eq!(get_package(&empty_vuln()), "—");
    }

    // --- get_fixed_version --------------------------------------------------

    #[test]
    fn get_fixed_version_extracts_fixed_event() {
        let mut vuln = empty_vuln();
        vuln.affected = Some(vec![OsvAffected {
            package: None,
            severity: None,
            ranges: Some(vec![OsvRange {
                r#type: "SEMVER".to_string(),
                repo: None,
                events: Some(vec![
                    OsvEvent { introduced: Some("0".to_string()), fixed: None, last_affected: None, limit: None },
                    OsvEvent { introduced: None, fixed: Some("2.32.0".to_string()), last_affected: None, limit: None },
                ]),
                database_specific: None,
            }]),
            versions: None,
            ecosystem_specific: None,
            database_specific: None,
        }]);
        assert_eq!(get_fixed_version(&vuln).unwrap(), "2.32.0");
    }

    #[test]
    fn get_fixed_version_returns_none_when_no_fix() {
        assert!(get_fixed_version(&empty_vuln()).is_none());
    }

    // --- get_advisory_url ---------------------------------------------------

    #[test]
    fn get_advisory_url_prefers_advisory_type() {
        let mut vuln = empty_vuln();
        vuln.references = Some(vec![
            OsvReference { r#type: "WEB".to_string(), url: "https://example.com/web".to_string() },
            OsvReference { r#type: "ADVISORY".to_string(), url: "https://example.com/advisory".to_string() },
        ]);
        assert_eq!(get_advisory_url(&vuln).unwrap(), "https://example.com/advisory");
    }

    #[test]
    fn get_advisory_url_falls_back_to_first_reference() {
        let mut vuln = empty_vuln();
        vuln.references = Some(vec![
            OsvReference { r#type: "WEB".to_string(), url: "https://example.com/first".to_string() },
        ]);
        assert_eq!(get_advisory_url(&vuln).unwrap(), "https://example.com/first");
    }

    #[test]
    fn get_advisory_url_returns_none_when_no_references() {
        assert!(get_advisory_url(&empty_vuln()).is_none());
    }
}
