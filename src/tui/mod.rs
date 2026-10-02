//! Read-only memory report UI. Layers overlap and must never be grand summed.
use crate::Result;
use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::{CrosstermBackend, TestBackend},
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    symbols::Marker,
    text::{Line, Span},
    widgets::{
        Axis, Block, Borders, Cell, Chart, Dataset, Gauge, GraphType, Paragraph, Row, Table,
        TableState, Tabs, Wrap,
    },
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, BufWriter, Read, Write},
    path::Path,
};
use unicode_width::UnicodeWidthChar;

const REPORT_LIMIT: u64 = 32 * 1024 * 1024;
const STACK_LIMIT: u64 = 8 * 1024 * 1024;
const STACK_SAMPLES: usize = 128;
const TREE_SCAN_LIMIT: u64 = 128 * 1024 * 1024;
const TREE_SAMPLE_LIMIT: usize = 4096;
const LIFETIME_LIMIT: u64 = 8 * 1024 * 1024;
const SECTIONS: [&str; 7] = [
    "Health",
    "Layers",
    "Cppgc types",
    "Allocator",
    "Call paths",
    "Lifecycle",
    "Activities",
];

struct Reports {
    phases: Vec<String>,
    pages: Vec<Vec<Vec<String>>>,
    target_pid: Option<u64>,
    trace_complete: Option<bool>,
    events_lost: Option<u64>,
    required_pdb_failures: usize,
    stack_domains: Vec<StackDomain>,
    stack_scan_truncated: bool,
    lifecycle: Option<Lifecycle>,
    projections: Projections,
    skipped_oversized: Vec<String>,
    activities: activities::ActivityReports,
}

#[derive(Default)]
struct Projections {
    runtime: Option<Value>,
    reader: Option<Value>,
    suites: Option<Value>,
    large: Option<Value>,
    sources: Vec<String>,
}

#[derive(Default)]
struct StackNode {
    label: String,
    source: String,
    inclusive: u64,
    self_weight: u64,
    samples: u64,
    allocation: AllocationBreakdown,
    children: BTreeMap<String, StackNode>,
}

#[derive(Default)]
struct AllocationBreakdown {
    observed_bytes: u64,
    requested_bytes: u64,
    kinds: BTreeMap<String, AllocationStat>,
    heaps: BTreeMap<String, AllocationStat>,
    allocation_ids: BTreeMap<u64, AllocationStat>,
}

#[derive(Default)]
struct AllocationStat {
    samples: u64,
    weight: u64,
}

struct AllocationObservation {
    observed_bytes: u64,
    requested_bytes: u64,
    kind: String,
    heap: Option<String>,
    allocation_id: Option<u64>,
}

struct StackDomain {
    title: &'static str,
    badge: &'static str,
    exact: bool,
    root: StackNode,
}

struct VisibleStack<'a> {
    id: String,
    depth: usize,
    node: &'a StackNode,
}

#[derive(Default)]
struct LifeObject {
    id: u64,
    bytes: u64,
    gc_info: u64,
    seeded: bool,
    events: Vec<LifeEvent>,
}

struct LifeEvent {
    sequence: u64,
    kind: String,
    gc_epoch: u64,
    bytes: u64,
}

struct Lifecycle {
    complete: bool,
    heap_id: String,
    live_objects: u64,
    live_bytes: u64,
    header_bytes: Option<u64>,
    known_payload_bytes: u64,
    known_padding_bytes: u64,
    unknown_requested_objects: u64,
    major_live_bytes: Vec<u64>,
    major_sequences: Vec<(u64, u64)>,
    capture_start_sequence: u64,
    inventory_end_sequence: u64,
    capture_end_sequence: u64,
    objects: Vec<LifeObject>,
    type_names: BTreeMap<u64, String>,
}

struct PopulationRow {
    id: String,
    depth: usize,
    gc_info: u64,
    label: String,
    object_indices: Vec<usize>,
    expandable: bool,
}

struct GcInterval {
    label: String,
    before_bytes: u64,
    allocated_bytes: u64,
    freed_bytes: u64,
    after_bytes: u64,
    contributors: Vec<TypeContribution>,
}

struct TypeContribution {
    gc_info: u64,
    delta_bytes: i64,
    after_bytes: u64,
}

mod activities;
mod loader;

use loader::*;

struct State {
    phase: usize,
    section: usize,
    offset: usize,
    legacy: bool,
    call_domain: usize,
    call_table: TableState,
    expanded: BTreeSet<String>,
    life_view: usize,
    life_metric: usize,
    life_profile_table: TableState,
    life_profile_expanded: BTreeSet<String>,
    life_timeline_table: TableState,
    life_contributor_table: TableState,
    life_timeline_focus_contributors: bool,
    life_selected_type: Option<u64>,
    life_table: TableState,
    projection_layers_mode: usize,
    projection_types_table: TableState,
    projection_allocator_table: TableState,
    projection_suite_table: TableState,
    projection_large_table: TableState,
    activity_table: TableState,
    activity_mode: usize,
}

impl State {
    fn new(reports: &Reports) -> Self {
        let mut call_table = TableState::default();
        call_table.select(Some(0));
        let mut life_table = TableState::default();
        life_table.select(Some(0));
        let mut life_profile_table = TableState::default();
        life_profile_table.select(Some(0));
        let mut life_timeline_table = TableState::default();
        life_timeline_table.select(Some(0));
        let mut life_contributor_table = TableState::default();
        life_contributor_table.select(Some(0));
        let mut projection_types_table = TableState::default();
        projection_types_table.select(Some(0));
        let mut projection_allocator_table = TableState::default();
        projection_allocator_table.select(Some(0));
        let mut projection_suite_table = TableState::default();
        projection_suite_table.select(Some(0));
        let mut projection_large_table = TableState::default();
        projection_large_table.select(Some(0));
        let mut state = Self {
            phase: 0,
            section: if !reports.activities.is_empty()
                && reports.target_pid.is_none()
                && reports.projections.sources.is_empty()
                && reports.lifecycle.is_none()
            {
                6
            } else {
                0
            },
            offset: 0,
            legacy: false,
            call_domain: 0,
            call_table,
            expanded: BTreeSet::new(),
            life_view: 0,
            life_metric: 0,
            life_profile_table,
            life_profile_expanded: BTreeSet::new(),
            life_timeline_table,
            life_contributor_table,
            life_timeline_focus_contributors: false,
            life_selected_type: None,
            life_table,
            projection_layers_mode: 0,
            projection_types_table,
            projection_allocator_table,
            projection_suite_table,
            projection_large_table,
            activity_table: TableState::default().with_selected(Some(0)),
            activity_mode: if reports.activities.composition.is_none() {
                1
            } else {
                0
            },
        };
        for (domain_index, domain) in reports.stack_domains.iter().enumerate() {
            let mut node = &domain.root;
            let mut id = domain_index.to_string();
            for _ in 0..3 {
                let Some((label, child)) = node
                    .children
                    .iter()
                    .max_by_key(|(_, child)| child.inclusive)
                else {
                    break;
                };
                id.push('\u{1f}');
                id.push_str(label);
                state.expanded.insert(id.clone());
                node = child;
            }
        }
        state
    }
}

fn wrapped(lines: &[String], width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut rows = Vec::new();
    for line in lines {
        let mut row = String::new();
        let mut used = 0;
        for c in line.chars().map(|c| if c.is_control() { ' ' } else { c }) {
            let cells = c.width().unwrap_or(0);
            if used + cells > width && !row.is_empty() {
                rows.push(std::mem::take(&mut row));
                used = 0;
            }
            row.push(c);
            used += cells;
        }
        rows.push(row);
    }
    rows
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn collect_visible_stacks<'a>(
    node: &'a StackNode,
    id: &str,
    depth: usize,
    expanded: &BTreeSet<String>,
    rows: &mut Vec<VisibleStack<'a>>,
) {
    let mut children = node.children.iter().collect::<Vec<_>>();
    children.sort_by(|a, b| b.1.inclusive.cmp(&a.1.inclusive).then_with(|| a.0.cmp(b.0)));
    for (label, child) in children {
        let child_id = format!("{id}\u{1f}{label}");
        rows.push(VisibleStack {
            id: child_id.clone(),
            depth,
            node: child,
        });
        if expanded.contains(&child_id) {
            collect_visible_stacks(child, &child_id, depth + 1, expanded, rows);
        }
    }
}

fn visible_stacks<'a>(reports: &'a Reports, state: &State) -> Vec<VisibleStack<'a>> {
    let mut rows = Vec::new();
    if let Some(domain) = reports.stack_domains.get(state.call_domain) {
        collect_visible_stacks(
            &domain.root,
            &state.call_domain.to_string(),
            0,
            &state.expanded,
            &mut rows,
        );
    }
    rows
}

fn selected_stack_id(reports: &Reports, state: &State) -> Option<String> {
    let selected = state.call_table.selected().unwrap_or(0);
    visible_stacks(reports, state)
        .get(selected)
        .map(|row| row.id.clone())
}

fn selected_stack_node<'a>(reports: &'a Reports, state: &State) -> Option<&'a StackNode> {
    let selected = state.call_table.selected().unwrap_or(0);
    visible_stacks(reports, state)
        .get(selected)
        .map(|row| row.node)
}

fn top_string(values: &BTreeMap<String, AllocationStat>) -> Option<&str> {
    values
        .iter()
        .max_by_key(|(_, stat)| stat.weight)
        .map(|(value, _)| value.as_str())
}

fn top_allocation_id(values: &BTreeMap<u64, AllocationStat>) -> Option<u64> {
    values
        .iter()
        .max_by_key(|(_, stat)| stat.weight)
        .map(|(value, _)| *value)
}

fn display_allocation_kind<'a>(reports: &'a Reports, kind: &'a str) -> String {
    let Some(gc_info) = kind
        .strip_prefix("cppgc GCInfo ")
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return kind.to_owned();
    };
    reports
        .lifecycle
        .as_ref()
        .and_then(|lifecycle| lifecycle.type_names.get(&gc_info))
        .map_or_else(
            || kind.to_owned(),
            |name| format!("{name} (GCInfo {gc_info})"),
        )
}

fn allocation_stack_path(node: &StackNode, id: u64, path: &str) -> Option<String> {
    for (label, child) in &node.children {
        if !child.allocation.allocation_ids.contains_key(&id) {
            continue;
        }
        let child_path = format!("{path}\u{1f}{label}");
        return allocation_stack_path(child, id, &child_path).or(Some(child_path));
    }
    None
}

fn focus_allocation_stack(reports: &Reports, state: &mut State, allocation_id: u64) -> bool {
    let Some((domain_index, domain)) =
        reports
            .stack_domains
            .iter()
            .enumerate()
            .find(|(_, domain)| {
                domain.exact
                    && domain
                        .root
                        .allocation
                        .allocation_ids
                        .contains_key(&allocation_id)
            })
    else {
        return false;
    };
    let Some(path) = allocation_stack_path(&domain.root, allocation_id, &domain_index.to_string())
    else {
        return false;
    };
    state.call_domain = domain_index;
    let mut prefix = domain_index.to_string();
    for component in path.split('\u{1f}').skip(1) {
        prefix.push('\u{1f}');
        prefix.push_str(component);
        state.expanded.insert(prefix.clone());
    }
    let selected = visible_stacks(reports, state)
        .iter()
        .position(|row| row.id == path)
        .unwrap_or(0);
    state.call_table.select(Some(selected));
    state.section = 4;
    true
}

fn draw_call_paths(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    reports: &Reports,
    state: &mut State,
) {
    let Some(domain) = reports.stack_domains.get(state.call_domain) else {
        frame.render_widget(Paragraph::new("No stack domains available"), area);
        return;
    };
    let rows = visible_stacks(reports, state);
    if rows.is_empty() {
        frame.render_widget(
            Paragraph::new("No allocation stacks found within the bounded symbolized.jsonl scan.")
                .block(Block::default().borders(Borders::ALL).title("Call paths")),
            area,
        );
        return;
    }
    let selected = state.call_table.selected().unwrap_or(0).min(rows.len() - 1);
    state.call_table.select(Some(selected));
    let badge_color = if domain.exact {
        Color::Green
    } else {
        Color::Magenta
    };
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" {} ", domain.title),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Metric: "),
        Span::styled("bytes", Style::default().fg(Color::Yellow)),
        Span::raw("  "),
        Span::styled(
            format!("[{}]", domain.badge),
            Style::default()
                .fg(badge_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            "  scan: {}{}",
            domain.root.samples,
            if reports.stack_scan_truncated {
                " stacks (bounded/truncated)"
            } else {
                " stacks"
            }
        )),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Attribution scope"),
    );
    let [header_area, body] =
        Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).areas(area);
    frame.render_widget(header, header_area);
    let split: [ratatui::layout::Rect; 2] = if body.width >= 100 {
        Layout::horizontal([Constraint::Percentage(70), Constraint::Percentage(30)]).areas(body)
    } else {
        Layout::vertical([Constraint::Percentage(65), Constraint::Percentage(35)]).areas(body)
    };
    let table_rows = rows.iter().map(|row| {
        let marker = if row.node.children.is_empty() {
            "•"
        } else if state.expanded.contains(&row.id) {
            "▼"
        } else {
            "▶"
        };
        let label = format!("{}{} {}", "  ".repeat(row.depth), marker, row.node.label);
        Row::new(vec![
            Cell::from(format_bytes(row.node.inclusive)),
            Cell::from(format_bytes(row.node.self_weight)),
            Cell::from(row.node.samples.to_string()),
            Cell::from(label),
        ])
    });
    let table = Table::new(
        table_rows,
        [
            Constraint::Length(11),
            Constraint::Length(11),
            Constraint::Length(8),
            Constraint::Min(24),
        ],
    )
    .header(
        Row::new(["Inclusive", "Self", "Samples", "Call path"]).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .row_highlight_style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::REVERSED | Modifier::BOLD),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Expandable stack tree"),
    );
    frame.render_stateful_widget(table, split[0], &mut state.call_table);
    let node = rows[selected].node;
    let ratio = if domain.root.inclusive == 0 {
        0.0
    } else {
        node.inclusive as f64 / domain.root.inclusive as f64
    };
    let [gauge_area, detail_area] =
        Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).areas(split[1]);
    frame.render_widget(
        Gauge::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Share of scanned weight"),
            )
            .gauge_style(Style::default().fg(badge_color))
            .ratio(ratio.clamp(0.0, 1.0))
            .label(format!("{:.1}%", ratio * 100.0)),
        gauge_area,
    );
    let observed_label = match state.call_domain {
        0 => "Requested bytes in sampled events",
        1 => "Allocated bytes in sampled events",
        _ => "Exact allocated capacity",
    };
    let mut details = vec![
        Line::from(Span::styled(
            &node.label,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(format!(
            "Inclusive weight: {}",
            format_bytes(node.inclusive)
        )),
        Line::from(format!(
            "Self weight:      {}",
            format_bytes(node.self_weight)
        )),
        Line::from(format!("Samples/events:   {}", node.samples)),
        Line::from(format!(
            "{observed_label}: {}",
            format_bytes(node.allocation.observed_bytes)
        )),
    ];
    if node.allocation.requested_bytes != 0
        && node.allocation.requested_bytes != node.allocation.observed_bytes
    {
        details.push(Line::from(format!(
            "Known requested payload: {}",
            format_bytes(node.allocation.requested_bytes)
        )));
    }
    details.extend([
        Line::from(""),
        Line::from(Span::styled(
            "Allocation classification",
            Style::default().fg(Color::Yellow),
        )),
    ]);
    let mut kinds = node.allocation.kinds.iter().collect::<Vec<_>>();
    kinds.sort_by_key(|(_, stat)| std::cmp::Reverse(stat.weight));
    for (kind, stat) in kinds.into_iter().take(3) {
        details.push(Line::from(format!(
            "{}  {} / {} events",
            display_allocation_kind(reports, kind),
            format_bytes(stat.weight),
            stat.samples
        )));
    }
    if let Some(heap) = top_string(&node.allocation.heaps) {
        details.push(Line::from(format!("Heap/root: {heap}")));
        details.push(Line::from(Span::styled(
            "[a] open matching Allocator root",
            Style::default().fg(Color::Cyan),
        )));
    }
    if let Some(id) = top_allocation_id(&node.allocation.allocation_ids) {
        details.push(Line::from(format!("Stable allocation ID: {id}")));
        details.push(Line::from(Span::styled(
            "[v] open object in Lifecycle",
            Style::default().fg(Color::Cyan),
        )));
    }
    details.extend([
        Line::from(""),
        Line::from(Span::styled("Source", Style::default().fg(Color::Yellow))),
        Line::from(node.source.as_str()),
        Line::from(""),
        Line::from(if domain.exact {
            "Exact cppgc allocated capacity; payload/header split is object-specific."
        } else {
            "Poisson-weighted allocation traffic; not retained bytes."
        }),
    ]);
    frame.render_widget(
        Paragraph::new(details).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Selected frame"),
        ),
        detail_area,
    );
}

mod lifecycle;
mod projections;

use lifecycle::*;
use projections::*;

fn draw(frame: &mut Frame, reports: &Reports, state: &mut State, rows: &[String]) {
    let areas = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(1),
        Constraint::Length(2),
    ])
    .split(frame.area());
    let complete = match reports.trace_complete {
        Some(true) => Span::styled("[COMPLETE]", Style::default().fg(Color::Green)),
        Some(false) => Span::styled("[INCOMPLETE]", Style::default().fg(Color::Yellow)),
        None => Span::styled("[UNKNOWN]", Style::default().fg(Color::Yellow)),
    };
    let loss = match reports.events_lost {
        Some(0) => Span::styled("[0 LOSS]", Style::default().fg(Color::Green)),
        Some(loss) => Span::styled(format!("[{loss} LOST]"), Style::default().fg(Color::Red)),
        None => Span::styled("[LOSS UNKNOWN]", Style::default().fg(Color::Yellow)),
    };
    let symbols = if reports.required_pdb_failures == 0 {
        Span::styled("[PDB OK]", Style::default().fg(Color::Green))
    } else {
        Span::styled(
            format!("[{} PDB FAIL]", reports.required_pdb_failures),
            Style::default().fg(Color::Red),
        )
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                " V8 Memory ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "│ PID {} │ {} │ ",
                reports
                    .target_pid
                    .map_or_else(|| "unknown".into(), |pid| pid.to_string()),
                if state.section == 6 {
                    reports
                        .activities
                        .names
                        .get(state.activity_table.selected().unwrap_or(0))
                        .map_or("No activity report", String::as_str)
                } else {
                    &reports.phases[state.phase]
                }
            )),
            complete,
            Span::raw(" "),
            loss,
            Span::raw(" "),
            symbols,
        ]))
        .block(
            Block::default()
                .title("Memory report")
                .borders(Borders::ALL),
        ),
        areas[0],
    );
    frame.render_widget(
        Tabs::new(SECTIONS.to_vec())
            .select(state.section)
            .highlight_style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL)),
        areas[1],
    );
    let height = usize::from(areas[2].height.saturating_sub(2));
    let start = state.offset.min(rows.len().saturating_sub(1));
    match state.section {
        0 if !state.legacy && reports.projections.reader.is_some() => {
            draw_projection_health(frame, areas[2], reports)
        }
        1 if !state.legacy && reports.projections.runtime.is_some() => {
            draw_projection_layers(frame, areas[2], reports, state)
        }
        2 if !state.legacy && reports.projections.runtime.is_some() => {
            draw_projection_types(frame, areas[2], reports, state)
        }
        3 if !state.legacy && reports.projections.runtime.is_some() => {
            draw_projection_allocator(frame, areas[2], reports, state)
        }
        4 if !state.legacy => draw_call_paths(frame, areas[2], reports, state),
        5 if !state.legacy && reports.lifecycle.is_some() => {
            draw_lifecycle(frame, areas[2], reports, state)
        }
        5 if !state.legacy && reports.projections.runtime.is_some() => {
            draw_projection_lifecycle(frame, areas[2], reports, state)
        }
        6 => activities::draw_activities(frame, areas[2], reports, state),
        _ => {
            let text = rows
                .iter()
                .skip(start)
                .take(height)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");
            frame.render_widget(
                Paragraph::new(text).block(Block::default().borders(Borders::ALL)),
                areas[2],
            );
        }
    }
    let help: String = match (state.section, state.legacy) {
        (_, true) => {
            "Headless compatibility page: complete legacy evidence follows the dashboard".into()
        }
        (6, false) => {
            "j/k: activity | m: composition/comparison | PgUp/PgDn: details | Tab: panels | q: exit"
                .into()
        }
        (4, false) => {
            "j/k: select | h/l: collapse/expand | m: domain | a: Allocator | v: Lifecycle | q: exit"
                .into()
        }
        (1, false) if reports.projections.runtime.is_some() => {
            "m: iteration trends / suite demand | [/]: projected iteration | q: exit".into()
        }
        (2, false) if reports.projections.runtime.is_some() => {
            "j/k: select type | [/]: projected iteration | q: exit".into()
        }
        (3, false) if reports.projections.runtime.is_some() => {
            "j/k: select slack observation | slack is not proven reclaimable | q: exit".into()
        }
        (5, false) if projection_lifecycle_active(reports, state) => {
            "j/k: select large allocation | g/G: first/last | Tab: next top-level view | q: exit"
                .into()
        }
        (5, false) => match state.life_view {
            0 => "j/k: select | h/l: expand | m: metric | t: Timeline | o: Objects | q: exit",
            1 => {
                "Tab: intervals/contributors | j/k: select | p: Profile | o: Objects | u: all types"
            }
            _ => "j/k: select object | c: origin when available | p: Profile | t: Timeline",
        }
        .into(),
        _ => "Tab: panels | j/k/PgUp/PgDn: scroll | [/]: checkpoint | q: exit".into(),
    };
    frame.render_widget(
        Paragraph::new(format!(
            "{help}\n{}",
            if state.section < 4 || state.legacy {
                format!(
                    "rows {}-{} / {}",
                    start + 1,
                    (start + height).min(rows.len()),
                    rows.len()
                )
            } else {
                "Evidence: exact, sampled, snapshot, and capture scopes never merge.".into()
            }
        )),
        areas[3],
    );
}

struct TerminalGuard {
    raw: bool,
    alternate: bool,
    cursor: bool,
}

impl TerminalGuard {
    fn enter() -> Result<Self> {
        let mut guard = Self {
            raw: false,
            alternate: false,
            cursor: false,
        };
        enable_raw_mode().map_err(|e| e.to_string())?;
        guard.raw = true;
        // Set flags before commands: even a partially written command needs undoing.
        guard.alternate = true;
        execute!(io::stdout(), EnterAlternateScreen).map_err(|e| e.to_string())?;
        guard.cursor = true;
        execute!(io::stdout(), Hide).map_err(|e| e.to_string())?;
        Ok(guard)
    }

    fn restore(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        if self.cursor {
            match execute!(io::stdout(), Show) {
                Ok(()) => self.cursor = false,
                Err(e) => errors.push(format!("restore cursor: {e}")),
            }
        }
        if self.alternate {
            match execute!(io::stdout(), LeaveAlternateScreen) {
                Ok(()) => self.alternate = false,
                Err(e) => errors.push(format!("leave alternate screen: {e}")),
            }
        }
        if self.raw {
            match disable_raw_mode() {
                Ok(()) => self.raw = false,
                Err(e) => errors.push(format!("disable raw mode: {e}")),
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            eprintln!("Memory viewer terminal cleanup failed: {error}");
        }
    }
}

/// View reports without reading the unbounded events.jsonl stream.
pub fn run(directory: &Path) -> Result<()> {
    let reports = Reports::load(directory)?;
    let mut guard = TerminalGuard::enter()?;
    let result = (|| {
        let mut terminal =
            Terminal::new(CrosstermBackend::new(io::stdout())).map_err(|e| e.to_string())?;
        let mut state = State::new(&reports);
        let mut cached = None;
        let mut content = Vec::new();
        loop {
            let width = terminal.size().map_err(|e| e.to_string())?.width;
            let key = (state.phase, state.section, width);
            if cached != Some(key) {
                content = wrapped(
                    &reports.pages[state.phase][state.section],
                    usize::from(width.saturating_sub(2)),
                );
                cached = Some(key);
                state.offset = state.offset.min(content.len().saturating_sub(1));
            }
            let rows = content.len();
            terminal
                .draw(|frame| draw(frame, &reports, &mut state, &content))
                .map_err(|e| e.to_string())?;
            if let Event::Key(key) = event::read().map_err(|e| e.to_string())? {
                if key.kind == KeyEventKind::Release {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Char('j') | KeyCode::Down if state.section == 6 => {
                        activities::select_activity(&reports, &mut state, 1);
                    }
                    KeyCode::Char('k') | KeyCode::Up if state.section == 6 => {
                        activities::select_activity(&reports, &mut state, -1);
                    }
                    KeyCode::Char('m') if state.section == 6 => {
                        activities::next_activity_mode(&mut state)
                    }
                    KeyCode::PageDown if state.section == 6 => {
                        state.offset = state.offset.saturating_add(10)
                    }
                    KeyCode::PageUp if state.section == 6 => {
                        state.offset = state.offset.saturating_sub(10)
                    }
                    KeyCode::Char('j') | KeyCode::Down
                        if projection_lifecycle_active(&reports, &state) =>
                    {
                        select_projected_large_allocation(&reports, &mut state, 1);
                    }
                    KeyCode::Char('k') | KeyCode::Up
                        if projection_lifecycle_active(&reports, &state) =>
                    {
                        select_projected_large_allocation(&reports, &mut state, -1);
                    }
                    KeyCode::Char('g') if projection_lifecycle_active(&reports, &state) => {
                        state.projection_large_table.select(Some(0));
                    }
                    KeyCode::Char('G') if projection_lifecycle_active(&reports, &state) => {
                        state.projection_large_table.select(Some(
                            projected_large_allocation_count(&reports).saturating_sub(1),
                        ));
                    }
                    KeyCode::Char('[')
                        if state.section == 5
                            && reports.lifecycle.is_some()
                            && state.life_view == 1 =>
                    {
                        let selected = state.life_timeline_table.selected().unwrap_or(0);
                        state
                            .life_timeline_table
                            .select(Some(selected.saturating_sub(1)));
                        state.life_contributor_table.select(Some(0));
                    }
                    KeyCode::Char(']')
                        if state.section == 5
                            && reports.lifecycle.is_some()
                            && state.life_view == 1 =>
                    {
                        let last = reports.lifecycle.as_ref().map_or(0, |lifecycle| {
                            gc_intervals(lifecycle, state.life_selected_type)
                                .len()
                                .saturating_sub(1)
                        });
                        let selected = state.life_timeline_table.selected().unwrap_or(0);
                        state
                            .life_timeline_table
                            .select(Some((selected + 1).min(last)));
                        state.life_contributor_table.select(Some(0));
                    }
                    KeyCode::Char('[') => {
                        state.phase = state.phase.saturating_sub(1);
                        state.offset = 0;
                    }
                    KeyCode::Char(']') => {
                        state.phase = (state.phase + 1).min(reports.phases.len() - 1);
                        state.offset = 0;
                    }
                    KeyCode::Tab | KeyCode::BackTab
                        if state.section == 5
                            && reports.lifecycle.is_some()
                            && state.life_view == 1 =>
                    {
                        state.life_timeline_focus_contributors =
                            !state.life_timeline_focus_contributors;
                    }
                    KeyCode::Tab | KeyCode::BackTab => {
                        state.section = if key.code == KeyCode::BackTab {
                            (state.section + SECTIONS.len() - 1) % SECTIONS.len()
                        } else {
                            (state.section + 1) % SECTIONS.len()
                        };
                        state.offset = 0;
                    }
                    KeyCode::Char('j') | KeyCode::Down if state.section == 4 => {
                        let last = visible_stacks(&reports, &state).len().saturating_sub(1);
                        let selected = state.call_table.selected().unwrap_or(0);
                        state.call_table.select(Some((selected + 1).min(last)));
                    }
                    KeyCode::Char('k') | KeyCode::Up if state.section == 4 => {
                        let selected = state.call_table.selected().unwrap_or(0);
                        state.call_table.select(Some(selected.saturating_sub(1)));
                    }
                    KeyCode::Char('h') | KeyCode::Left if state.section == 4 => {
                        if let Some(id) = selected_stack_id(&reports, &state) {
                            state.expanded.remove(&id);
                            let last = visible_stacks(&reports, &state).len().saturating_sub(1);
                            let selected = state.call_table.selected().unwrap_or(0).min(last);
                            state.call_table.select(Some(selected));
                        }
                    }
                    KeyCode::Char('l') | KeyCode::Right if state.section == 4 => {
                        if let Some(id) = selected_stack_id(&reports, &state) {
                            state.expanded.insert(id);
                        }
                    }
                    KeyCode::Char('m') if state.section == 4 => {
                        state.call_domain =
                            (state.call_domain + 1) % reports.stack_domains.len().max(1);
                        state.call_table.select(Some(0));
                    }
                    KeyCode::Char('m')
                        if state.section == 1 && reports.projections.runtime.is_some() =>
                    {
                        state.projection_layers_mode = (state.projection_layers_mode + 1)
                            % if reports.projections.suites.is_some() {
                                2
                            } else {
                                1
                            };
                    }
                    KeyCode::Char('j') | KeyCode::Down
                        if state.section == 1 && state.projection_layers_mode == 1 =>
                    {
                        let last =
                            projection_array(&reports.projections, "suites", "ranked_suite_costs")
                                .map_or(0, |rows| rows.len().saturating_sub(1));
                        let selected = state.projection_suite_table.selected().unwrap_or(0);
                        state
                            .projection_suite_table
                            .select(Some((selected + 1).min(last)));
                    }
                    KeyCode::Char('k') | KeyCode::Up
                        if state.section == 1 && state.projection_layers_mode == 1 =>
                    {
                        let selected = state.projection_suite_table.selected().unwrap_or(0);
                        state
                            .projection_suite_table
                            .select(Some(selected.saturating_sub(1)));
                    }
                    KeyCode::Char('j') | KeyCode::Down
                        if state.section == 2 && reports.projections.runtime.is_some() =>
                    {
                        let last = projection_array(
                            &reports.projections,
                            "runtime",
                            "cppgc_types_by_median_iteration_footprint",
                        )
                        .map_or(0, |rows| rows.len().saturating_sub(1));
                        let selected = state.projection_types_table.selected().unwrap_or(0);
                        state
                            .projection_types_table
                            .select(Some((selected + 1).min(last)));
                    }
                    KeyCode::Char('k') | KeyCode::Up
                        if state.section == 2 && reports.projections.runtime.is_some() =>
                    {
                        let selected = state.projection_types_table.selected().unwrap_or(0);
                        state
                            .projection_types_table
                            .select(Some(selected.saturating_sub(1)));
                    }
                    KeyCode::Char('j') | KeyCode::Down
                        if state.section == 3 && reports.projections.runtime.is_some() =>
                    {
                        let last = projection_array(
                            &reports.projections,
                            "runtime",
                            "largest_bucket_slack_observations",
                        )
                        .map_or(0, |rows| rows.len().saturating_sub(1));
                        let selected = state.projection_allocator_table.selected().unwrap_or(0);
                        state
                            .projection_allocator_table
                            .select(Some((selected + 1).min(last)));
                    }
                    KeyCode::Char('k') | KeyCode::Up
                        if state.section == 3 && reports.projections.runtime.is_some() =>
                    {
                        let selected = state.projection_allocator_table.selected().unwrap_or(0);
                        state
                            .projection_allocator_table
                            .select(Some(selected.saturating_sub(1)));
                    }
                    KeyCode::Char('a') if state.section == 4 => {
                        if let Some(heap) = selected_stack_node(&reports, &state)
                            .and_then(|node| top_string(&node.allocation.heaps))
                        {
                            state.section = 3;
                            state.offset = reports.pages[state.phase][3]
                                .iter()
                                .position(|line| line.contains(heap))
                                .unwrap_or(0);
                        }
                    }
                    KeyCode::Char('v') if state.section == 4 => {
                        if let Some(id) = selected_stack_node(&reports, &state)
                            .and_then(|node| top_allocation_id(&node.allocation.allocation_ids))
                            && let Some(lifecycle) = &reports.lifecycle
                            && let Some(index) =
                                lifecycle.objects.iter().position(|object| object.id == id)
                        {
                            let gc_info = lifecycle.objects[index].gc_info;
                            state.life_selected_type = Some(gc_info);
                            let filtered = lifecycle
                                .objects
                                .iter()
                                .enumerate()
                                .filter(|(_, object)| object.gc_info == gc_info)
                                .position(|(object_index, _)| object_index == index)
                                .unwrap_or(0);
                            state.life_table.select(Some(filtered));
                            state.life_view = 2;
                            state.section = 5;
                        }
                    }
                    KeyCode::Char('1') | KeyCode::Char('p')
                        if state.section == 5 && reports.lifecycle.is_some() =>
                    {
                        state.life_view = 0;
                    }
                    KeyCode::Char('2') | KeyCode::Char('t')
                        if state.section == 5 && reports.lifecycle.is_some() =>
                    {
                        state.life_view = 1;
                    }
                    KeyCode::Char('3') | KeyCode::Char('o')
                        if state.section == 5 && reports.lifecycle.is_some() =>
                    {
                        state.life_view = 2;
                        state.life_table.select(Some(0));
                    }
                    KeyCode::Char('u')
                        if state.section == 5
                            && reports.lifecycle.is_some()
                            && state.life_view == 1 =>
                    {
                        state.life_selected_type = None;
                        state.life_contributor_table.select(Some(0));
                    }
                    KeyCode::Char('m')
                        if state.section == 5
                            && reports.lifecycle.is_some()
                            && state.life_view == 0 =>
                    {
                        state.life_metric = (state.life_metric + 1) % 5;
                        state.life_profile_table.select(Some(0));
                    }
                    KeyCode::Char('j') | KeyCode::Down
                        if state.section == 5
                            && reports.lifecycle.is_some()
                            && state.life_view == 0 =>
                    {
                        let last = reports.lifecycle.as_ref().map_or(0, |lifecycle| {
                            population_rows(lifecycle, &state).len().saturating_sub(1)
                        });
                        let selected = state.life_profile_table.selected().unwrap_or(0);
                        state
                            .life_profile_table
                            .select(Some((selected + 1).min(last)));
                    }
                    KeyCode::Char('k') | KeyCode::Up
                        if state.section == 5
                            && reports.lifecycle.is_some()
                            && state.life_view == 0 =>
                    {
                        let selected = state.life_profile_table.selected().unwrap_or(0);
                        state
                            .life_profile_table
                            .select(Some(selected.saturating_sub(1)));
                    }
                    KeyCode::Char('h') | KeyCode::Left
                        if state.section == 5
                            && reports.lifecycle.is_some()
                            && state.life_view == 0 =>
                    {
                        if let Some(lifecycle) = &reports.lifecycle {
                            let rows = population_rows(lifecycle, &state);
                            if let Some(row) =
                                rows.get(state.life_profile_table.selected().unwrap_or(0))
                            {
                                state.life_profile_expanded.remove(&row.id);
                            }
                        }
                    }
                    KeyCode::Char('l') | KeyCode::Right | KeyCode::Enter
                        if state.section == 5
                            && reports.lifecycle.is_some()
                            && state.life_view == 0 =>
                    {
                        if let Some(lifecycle) = &reports.lifecycle {
                            let rows = population_rows(lifecycle, &state);
                            if let Some(row) =
                                rows.get(state.life_profile_table.selected().unwrap_or(0))
                                && row.expandable
                            {
                                state.life_profile_expanded.insert(row.id.clone());
                            }
                        }
                    }
                    KeyCode::Char('j') | KeyCode::Down
                        if state.section == 5
                            && reports.lifecycle.is_some()
                            && state.life_view == 1 =>
                    {
                        if let Some(lifecycle) = &reports.lifecycle {
                            let intervals = gc_intervals(lifecycle, state.life_selected_type);
                            if state.life_timeline_focus_contributors {
                                let interval = intervals
                                    .get(state.life_timeline_table.selected().unwrap_or(0));
                                let last = interval.map_or(0, |interval| {
                                    interval.contributors.len().saturating_sub(1)
                                });
                                let selected = state.life_contributor_table.selected().unwrap_or(0);
                                state
                                    .life_contributor_table
                                    .select(Some((selected + 1).min(last)));
                            } else {
                                let last = intervals.len().saturating_sub(1);
                                let selected = state.life_timeline_table.selected().unwrap_or(0);
                                state
                                    .life_timeline_table
                                    .select(Some((selected + 1).min(last)));
                                state.life_contributor_table.select(Some(0));
                            }
                        }
                    }
                    KeyCode::Char('k') | KeyCode::Up
                        if state.section == 5
                            && reports.lifecycle.is_some()
                            && state.life_view == 1 =>
                    {
                        if state.life_timeline_focus_contributors {
                            let selected = state.life_contributor_table.selected().unwrap_or(0);
                            state
                                .life_contributor_table
                                .select(Some(selected.saturating_sub(1)));
                        } else {
                            let selected = state.life_timeline_table.selected().unwrap_or(0);
                            state
                                .life_timeline_table
                                .select(Some(selected.saturating_sub(1)));
                            state.life_contributor_table.select(Some(0));
                        }
                    }
                    KeyCode::Enter
                        if state.section == 5
                            && reports.lifecycle.is_some()
                            && state.life_view == 1 =>
                    {
                        if let Some(lifecycle) = &reports.lifecycle {
                            let intervals = gc_intervals(lifecycle, state.life_selected_type);
                            if let Some(contributor) = intervals
                                .get(state.life_timeline_table.selected().unwrap_or(0))
                                .and_then(|interval| {
                                    interval
                                        .contributors
                                        .get(state.life_contributor_table.selected().unwrap_or(0))
                                })
                            {
                                state.life_selected_type = Some(contributor.gc_info);
                                state.life_view = 0;
                            }
                        }
                    }
                    KeyCode::Char('j') | KeyCode::Down
                        if state.section == 5
                            && reports.lifecycle.is_some()
                            && state.life_view == 2 =>
                    {
                        let last = reports.lifecycle.as_ref().map_or(0, |lifecycle| {
                            lifecycle
                                .objects
                                .iter()
                                .filter(|object| {
                                    state
                                        .life_selected_type
                                        .is_none_or(|gc_info| object.gc_info == gc_info)
                                })
                                .count()
                                .saturating_sub(1)
                        });
                        let selected = state.life_table.selected().unwrap_or(0);
                        state.life_table.select(Some((selected + 1).min(last)));
                    }
                    KeyCode::Char('k') | KeyCode::Up
                        if state.section == 5
                            && reports.lifecycle.is_some()
                            && state.life_view == 2 =>
                    {
                        let selected = state.life_table.selected().unwrap_or(0);
                        state.life_table.select(Some(selected.saturating_sub(1)));
                    }
                    KeyCode::Char('c')
                        if state.section == 5
                            && reports.lifecycle.is_some()
                            && state.life_view == 2 =>
                    {
                        if let Some(lifecycle) = &reports.lifecycle
                            && let Some(relative) = state.life_table.selected()
                            && let Some(object) = lifecycle
                                .objects
                                .iter()
                                .filter(|object| {
                                    state
                                        .life_selected_type
                                        .is_none_or(|gc_info| object.gc_info == gc_info)
                                })
                                .nth(relative)
                        {
                            focus_allocation_stack(&reports, &mut state, object.id);
                        }
                    }
                    KeyCode::Char('j') | KeyCode::Down => {
                        state.offset = (state.offset + 1).min(rows.saturating_sub(1))
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        state.offset = state.offset.saturating_sub(1)
                    }
                    KeyCode::PageDown => {
                        state.offset = (state.offset + 20).min(rows.saturating_sub(1))
                    }
                    KeyCode::PageUp => state.offset = state.offset.saturating_sub(20),
                    KeyCode::Home => state.offset = 0,
                    KeyCode::End => state.offset = rows.saturating_sub(1),
                    _ => {}
                }
            }
        }
        Ok(())
    })();
    let cleanup = guard.restore();
    match (result, cleanup) {
        (Err(error), Err(cleanup)) => Err(format!("{error}; {cleanup}")),
        (Err(error), _) | (_, Err(error)) => Err(error),
        _ => Ok(()),
    }
}

/// Write all phases/sections as paginated TestBackend text, refusing overwrite.
pub fn render_once(directory: &Path, output: &Path) -> Result<()> {
    let reports = Reports::load(directory)?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|e| format!("{}: {e}", output.display()))?;
    let mut writer = BufWriter::new(file);
    let mut terminal = Terminal::new(TestBackend::new(120, 32)).map_err(|e| e.to_string())?;
    let phase_count = if reports.projections.runtime.is_some() {
        1
    } else {
        reports.phases.len()
    };
    for phase in 0..phase_count {
        for section in 0..SECTIONS.len() {
            if section == 6 && phase > 0 {
                continue;
            }
            let mut state = State::new(&reports);
            state.phase = phase;
            state.section = section;
            let content = wrapped(&reports.pages[phase][section], 118);
            if section == 6 {
                for selected in 0..reports.activities.names.len().max(1) {
                    state.activity_table.select(Some(selected));
                    for mode in 0..2 {
                        if reports.activities.report(mode).is_none() {
                            continue;
                        }
                        state.activity_mode = mode;
                        let rows = wrapped(&reports.activities.details(&state), 80).len();
                        for offset in (0..rows.max(1)).step_by(8) {
                            state.offset = offset;
                            terminal
                                .draw(|frame| draw(frame, &reports, &mut state, &content))
                                .map_err(|e| e.to_string())?;
                            for y in 0..32 {
                                let buffer = terminal.backend().buffer();
                                let line: String =
                                    (0..120).map(|x| buffer[(x, y)].symbol()).collect();
                                writeln!(writer, "{}", line.trim_end())
                                    .map_err(|e| e.to_string())?;
                            }
                            writeln!(writer).map_err(|e| e.to_string())?;
                        }
                    }
                }
                continue;
            }
            loop {
                terminal
                    .draw(|frame| draw(frame, &reports, &mut state, &content))
                    .map_err(|e| e.to_string())?;
                for y in 0..32 {
                    let buffer = terminal.backend().buffer();
                    let line: String = (0..120).map(|x| buffer[(x, y)].symbol()).collect();
                    writeln!(writer, "{}", line.trim_end()).map_err(|e| e.to_string())?;
                }
                writeln!(writer).map_err(|e| e.to_string())?;
                if section == 1
                    && !state.legacy
                    && state.projection_layers_mode == 0
                    && reports.projections.suites.is_some()
                {
                    state.projection_layers_mode = 1;
                    continue;
                }
                if section == 4
                    && !state.legacy
                    && state.call_domain + 1 < reports.stack_domains.len()
                {
                    state.call_domain += 1;
                    state.call_table.select(Some(0));
                    continue;
                }
                if section == 5
                    && !state.legacy
                    && reports.lifecycle.is_some()
                    && state.life_view < 2
                {
                    state.life_view += 1;
                    continue;
                }
                let projection_dashboard = !state.legacy
                    && match section {
                        0 => reports.projections.reader.is_some(),
                        1..=3 => reports.projections.runtime.is_some(),
                        5 => reports.lifecycle.is_none() && reports.projections.runtime.is_some(),
                        _ => false,
                    };
                if projection_dashboard {
                    break;
                }
                if section >= 4 && !state.legacy && reports.projections.sources.is_empty() {
                    state.legacy = true;
                    state.offset = 0;
                    continue;
                }
                if section >= 4 && !state.legacy {
                    break;
                }
                state.offset += 22;
                if state.offset >= content.len() {
                    break;
                }
            }
        }
    }
    writer.flush().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn stack_frames() -> Vec<Value> {
        vec![
            json!({
                "function": "Allocate",
                "module": "electron.exe",
                "source_file": "allocator.cc",
                "source_line": 42,
                "status": "pdb"
            }),
            json!({
                "function": "Work",
                "module": "electron.exe",
                "source_file": "work.cc",
                "source_line": 7,
                "status": "pdb"
            }),
        ]
    }

    fn reports() -> Reports {
        let mut root = StackNode::default();
        insert_stack(&mut root, &stack_frames(), 4096, &observation());
        let object = LifeObject {
            id: 448,
            bytes: 4112,
            gc_info: 127,
            seeded: false,
            events: vec![
                LifeEvent {
                    sequence: 448,
                    kind: "4".into(),
                    gc_epoch: 0,
                    bytes: 4112,
                },
                LifeEvent {
                    sequence: 850,
                    kind: "5".into(),
                    gc_epoch: 2,
                    bytes: 4112,
                },
            ],
        };
        Reports {
            phases: vec!["Checkpoint 1: fixture-rooted (complete=true)".into()],
            pages: vec![vec![vec!["legacy".into()]; SECTIONS.len()]],
            activities: activities::ActivityReports::default(),
            target_pid: Some(41608),
            trace_complete: Some(true),
            events_lost: Some(0),
            required_pdb_failures: 0,
            stack_domains: vec![StackDomain {
                title: "Cppgc lifecycle",
                badge: "EXACT ALLOCATIONS",
                exact: true,
                root,
            }],
            stack_scan_truncated: false,
            lifecycle: Some(Lifecycle {
                complete: true,
                heap_id: "heap#0".into(),
                live_objects: 0,
                live_bytes: 0,
                header_bytes: Some(8),
                known_payload_bytes: 4097,
                known_padding_bytes: 7,
                unknown_requested_objects: 0,
                major_live_bytes: vec![4112, 4112, 0],
                major_sequences: vec![(600, 1), (800, 2), (900, 3)],
                capture_start_sequence: 1,
                inventory_end_sequence: 400,
                capture_end_sequence: 976,
                objects: vec![object],
                type_names: BTreeMap::from([(127, "RetentionFixture".into())]),
            }),
            projections: Projections::default(),
            skipped_oversized: Vec::new(),
        }
    }

    fn observation() -> AllocationObservation {
        AllocationObservation {
            observed_bytes: 4112,
            requested_bytes: 4097,
            kind: "cppgc GCInfo 127".into(),
            heap: Some("heap#0".into()),
            allocation_id: Some(448),
        }
    }

    fn rendered_text(terminal: &Terminal<TestBackend>) -> String {
        let buffer = terminal.backend().buffer();
        let area = terminal.size().unwrap();
        (0..area.height)
            .flat_map(|y| {
                (0..area.width)
                    .map(move |x| buffer[(x, y)].symbol())
                    .chain(std::iter::once("\n"))
            })
            .collect()
    }

    #[test]
    fn stack_tree_keeps_self_and_inclusive_weights_distinct() {
        let mut root = StackNode::default();
        insert_stack(&mut root, &stack_frames(), 4096, &observation());
        insert_stack(&mut root, &stack_frames(), 2048, &observation());
        let work = &root.children["electron.exe!Work"];
        let allocate = &work.children["electron.exe!Allocate"];
        assert_eq!(root.inclusive, 6144);
        assert_eq!(work.inclusive, 6144);
        assert_eq!(work.self_weight, 0);
        assert_eq!(allocate.inclusive, 6144);
        assert_eq!(allocate.self_weight, 6144);
        assert_eq!(allocate.samples, 2);
        assert_eq!(allocate.allocation.observed_bytes, 8224);
        assert_eq!(
            top_allocation_id(&allocate.allocation.allocation_ids),
            Some(448)
        );
    }

    #[test]
    fn stack_tree_expansion_controls_visible_rows() {
        let reports = reports();
        let mut state = State::new(&reports);
        let expanded = visible_stacks(&reports, &state);
        assert_eq!(expanded.len(), 2);
        state.expanded.clear();
        let collapsed = visible_stacks(&reports, &state);
        assert_eq!(collapsed.len(), 1);
        assert_eq!(collapsed[0].node.label, "electron.exe!Work");
    }

    #[test]
    fn object_timeline_interleaves_major_gc_boundaries() {
        let reports = reports();
        let lifecycle = reports.lifecycle.as_ref().unwrap();
        let lines = object_timeline(lifecycle, &lifecycle.objects[0]);
        let text = lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("seq  448 alloc"));
        assert!(text.contains("seq  600 major GC 1 end"));
        assert!(text.contains("seq  800 major GC 2 end"));
        assert!(text.contains("seq  850 free"));
        assert!(!text.contains("major GC 3"));
    }

    #[test]
    fn call_paths_render_as_expandable_exact_tree() {
        let reports = reports();
        let mut state = State::new(&reports);
        state.section = 4;
        let mut terminal = Terminal::new(TestBackend::new(120, 32)).unwrap();
        terminal
            .draw(|frame| draw(frame, &reports, &mut state, &[]))
            .unwrap();
        let text = rendered_text(&terminal);
        assert!(text.contains("Expandable stack tree"));
        assert!(text.contains("EXACT ALLOCATIONS"));
        assert!(text.contains("Inclusive"));
        assert!(text.contains("electron.exe!Work"));
        assert!(text.contains("Allocation classification"));
        assert!(text.contains("RetentionFixture (GCInfo 127)"));
        assert!(text.contains("[v] open object in Lifecycle"));
    }

    #[test]
    fn lifecycle_renders_capture_scope_and_stable_object_timeline() {
        let reports = reports();
        let mut state = State::new(&reports);
        state.section = 5;
        state.life_view = 2;
        let mut terminal = Terminal::new(TestBackend::new(120, 32)).unwrap();
        terminal
            .draw(|frame| draw(frame, &reports, &mut state, &[]))
            .unwrap();
        let text = rendered_text(&terminal);
        assert!(text.contains("Object Inspector"));
        assert!(text.contains("CAPTURE COMPLETE"));
        assert!(text.contains("Stable ID"));
        assert!(text.contains("448"));
        assert!(text.contains("Selected object lifetime across the capture"));
        assert!(text.contains("A allocation"));
        assert!(text.contains("Retainers"));
        assert!(text.contains("no reference edges"));
        assert!(text.contains("major GC 1 end"));
    }

    #[test]
    fn retention_profile_defaults_to_type_level_cost_centers() {
        let reports = reports();
        let mut state = State::new(&reports);
        state.section = 5;
        state.life_view = 0;
        let mut terminal = Terminal::new(TestBackend::new(120, 32)).unwrap();
        terminal
            .draw(|frame| draw(frame, &reports, &mut state, &[]))
            .unwrap();
        let text = rendered_text(&terminal);
        assert!(text.contains("Retention Profile"));
        assert!(text.contains("Type → cohort → object"));
        assert!(text.contains("RetentionFixture"));
        assert!(text.contains("Fates:"));
        assert!(!text.contains("Object 448"));
    }

    #[test]
    fn gc_timeline_renders_intervals_and_type_contributors() {
        let reports = reports();
        let mut state = State::new(&reports);
        state.section = 5;
        state.life_view = 1;
        let mut terminal = Terminal::new(TestBackend::new(120, 32)).unwrap();
        terminal
            .draw(|frame| draw(frame, &reports, &mut state, &[]))
            .unwrap();
        let text = rendered_text(&terminal);
        assert!(text.contains("GC Timeline"));
        assert!(text.contains("GC intervals"));
        assert!(text.contains("Seed → GC 1"));
        assert!(text.contains("Type contributor"));
    }

    #[test]
    fn allocation_links_round_trip_between_stack_and_lifecycle() {
        let reports = reports();
        let mut state = State::new(&reports);
        assert!(focus_allocation_stack(&reports, &mut state, 448));
        assert_eq!(state.section, 4);
        let node = selected_stack_node(&reports, &state).unwrap();
        assert_eq!(
            top_allocation_id(&node.allocation.allocation_ids),
            Some(448)
        );
        let index = reports
            .lifecycle
            .as_ref()
            .unwrap()
            .objects
            .iter()
            .position(|object| object.id == 448)
            .unwrap();
        state.life_table.select(Some(index));
        assert_eq!(reports.lifecycle.as_ref().unwrap().objects[index].id, 448);
    }

    #[test]
    fn projected_lifecycle_selection_moves_and_updates_details() {
        let mut reports = reports();
        reports.lifecycle = None;
        reports.projections.runtime = Some(json!({"lifetime_heaps": []}));
        reports.projections.large = Some(json!({
            "heaps": {
                "heap": {
                    "largest_allocations": [
                        {"allocation_id": 1, "type_name": "First", "bytes": 65536,
                         "gc_info": 1, "allocated_at": "10", "freed_at": "20"},
                        {"allocation_id": 2, "type_name": "Second", "bytes": 131072,
                         "gc_info": 2, "allocated_at": "30", "freed_at": null}
                    ]
                }
            }
        }));
        let mut state = State::new(&reports);
        state.section = 5;
        assert!(projection_lifecycle_active(&reports, &state));
        assert_eq!(projected_large_allocation_count(&reports), 2);
        select_projected_large_allocation(&reports, &mut state, 1);
        assert_eq!(state.projection_large_table.selected(), Some(1));

        let mut terminal = Terminal::new(TestBackend::new(120, 32)).unwrap();
        terminal
            .draw(|frame| draw(frame, &reports, &mut state, &[]))
            .unwrap();
        let text = rendered_text(&terminal);
        assert!(text.contains("ID 2"));
        assert!(text.contains("Second"));
        assert!(text.contains("Selected large allocation"));

        select_projected_large_allocation(&reports, &mut state, -1);
        assert_eq!(state.projection_large_table.selected(), Some(0));
    }
}
