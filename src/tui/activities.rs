use super::*;

#[derive(Default)]
pub(super) struct ActivityReports {
    pub(super) composition: Option<Value>,
    comparison: Option<Value>,
    pub(super) names: Vec<String>,
}

impl ActivityReports {
    pub(super) fn load(input: &Path) -> Result<Self> {
        let mut reports = Self::default();
        let inputs = if input.is_file() {
            vec![input.to_owned()]
        } else {
            ["composition.json", "comparison.json"]
                .into_iter()
                .map(|name| input.join(name))
                .filter(|path| path.exists())
                .collect()
        };
        let mut names = BTreeSet::new();
        for path in inputs {
            let bytes = read_bounded(&path, REPORT_LIMIT)?.ok_or("Activity report disappeared.")?;
            let value: Value =
                serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
            if value["schema_version"].as_u64() != Some(1) {
                return Err(format!(
                    "{}: unsupported activity report schema",
                    path.display()
                ));
            }
            let plans = value["plans"]
                .as_object()
                .ok_or("Activity report plans must be an object.")?;
            let composition = value.get("snapshot_count").is_some();
            let comparison = value.get("pair_ids").is_some() || value.get("seeds").is_some();
            if composition == comparison {
                return Err(
                    "Expected a composition or comparison report, not an arbitrary JSON file."
                        .into(),
                );
            }
            for (name, row) in plans {
                if !row.is_object() {
                    return Err(format!("Activity {name}: expected an object."));
                }
                if composition {
                    for point in ["entry", "snapshot_peak", "end"] {
                        let object = row[point]
                            .as_object()
                            .ok_or_else(|| format!("Activity {name}: {point} missing/invalid."))?;
                        for (key, metric) in object {
                            if key.ends_with("_bytes")
                                && !metric.is_null()
                                && metric.as_u64().is_none()
                            {
                                return Err(format!("Activity {name}: invalid byte metric {key}."));
                            }
                        }
                    }
                } else {
                    if !row["paired_runs"].is_array() {
                        return Err(format!("Activity {name}: paired_runs missing/invalid."));
                    }
                    validate_measurements(row, name)?;
                }
                names.insert(name.clone());
            }
            let destination = if composition {
                &mut reports.composition
            } else {
                &mut reports.comparison
            };
            if destination.replace(value).is_some() {
                return Err("Duplicate activity report kind.".into());
            }
        }
        reports.names = names.into_iter().collect();
        Ok(reports)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
    pub(super) fn report(&self, mode: usize) -> Option<&Value> {
        if mode == 0 {
            self.composition.as_ref()
        } else {
            self.comparison.as_ref()
        }
    }
    fn selected<'a>(&'a self, state: &State) -> Option<(&'a str, &'a Value)> {
        let name = self
            .names
            .get(state.activity_table.selected().unwrap_or(0))?;
        self.report(state.activity_mode)?
            .get("plans")?
            .get(name)
            .map(|row| (name.as_str(), row))
    }
    pub(super) fn details(&self, state: &State) -> Vec<String> {
        let Some((_, row)) = self.selected(state) else {
            return vec![
                "Selected activity has no report in this view; missing is NOT zero.".into(),
            ];
        };
        let mut lines = Vec::new();
        flatten("", row, &mut lines);
        if let Some(report) = self.report(state.activity_mode) {
            lines.push("Report scope and limitations".into());
            for (key, value) in report.as_object().into_iter().flatten() {
                if key != "plans" {
                    flatten(key, value, &mut lines);
                }
            }
        }
        lines
    }
}

fn flatten(path: &str, value: &Value, lines: &mut Vec<String>) {
    match value {
        Value::Object(fields) => {
            if fields.is_empty() {
                lines.push(format!("{path}: none recorded"));
            }
            for (key, value) in fields {
                flatten(
                    &if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    },
                    value,
                    lines,
                );
            }
        }
        Value::Array(items) => {
            if items.is_empty() {
                lines.push(format!("{path}: no observations"));
            }
            for (index, value) in items.iter().enumerate() {
                flatten(&format!("{path}[{index}]"), value, lines);
            }
        }
        Value::Null => lines.push(format!("{path}: unavailable")),
        Value::String(text) => lines.push(format!("{path}: {text}")),
        _ => lines.push(format!("{path}: {value}")),
    }
}

fn validate_measurements(value: &Value, path: &str) -> Result<()> {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                let path = format!("{path}.{key}");
                let numeric = key.ends_with("_bytes")
                    || key.ends_with("_ms")
                    || key.ends_with("_percent")
                    || matches!(
                        key.as_str(),
                        "median" | "minimum" | "maximum" | "control_score" | "candidate_score"
                    );
                if numeric
                    && !value.is_object()
                    && !value.is_null()
                    && !value.as_f64().is_some_and(|x| x.is_finite())
                {
                    return Err(format!("{path}: expected numeric measurement or null."));
                }
                validate_measurements(value, &path)?;
            }
        }
        Value::Array(items) => {
            for (index, value) in items.iter().enumerate() {
                validate_measurements(value, &format!("{path}[{index}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn bytes(value: Option<&Value>) -> String {
    value.and_then(Value::as_u64).map_or_else(
        || "unavailable".into(),
        |bytes| format!("{:.2} MiB", mib(bytes)),
    )
}
fn change(value: &Value, key: &str) -> String {
    value["paired_metric_summary"][key]["median"]
        .as_f64()
        .map_or_else(|| "unavailable".into(), |number| format!("{number:+.2}%"))
}

pub(super) fn select_activity(reports: &Reports, state: &mut State, delta: isize) {
    let selected = state.activity_table.selected().unwrap_or(0);
    let next = selected
        .saturating_add_signed(delta)
        .min(reports.activities.names.len().saturating_sub(1));
    state.activity_table.select(Some(next));
    state.offset = 0;
}

pub(super) fn draw_activities(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    reports: &Reports,
    state: &mut State,
) {
    let activity = &reports.activities;
    let columns =
        Layout::horizontal([Constraint::Percentage(25), Constraint::Percentage(75)]).split(area);
    let rows = activity
        .names
        .iter()
        .map(|name| Row::new(vec![name.clone()]));
    frame.render_stateful_widget(
        Table::new(rows, [Constraint::Min(1)])
            .header(Row::new(vec!["Activity"]))
            .row_highlight_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ")
            .block(Block::default().borders(Borders::ALL).title("Activities")),
        columns[0],
        &mut state.activity_table,
    );
    let panels = Layout::vertical([Constraint::Length(10), Constraint::Min(1)]).split(columns[1]);
    let title = if state.activity_mode == 0 {
        "Composition | non-additive bytes"
    } else {
        "Comparison | paired changes"
    };
    if let Some((name, row)) = activity.selected(state) {
        if state.activity_mode == 0 {
            let metrics = [
                ("Process private", "process_private_bytes"),
                ("Working set", "process_working_set_bytes"),
                ("V8 committed", "v8_heap_committed_bytes"),
                ("V8 accounted used", "v8_heap_accounted_used_bytes"),
                ("Backing stores", "v8_backing_store_counter_bytes"),
            ];
            let rows = metrics.into_iter().map(|(label, key)| {
                Row::new(vec![
                    label.into(),
                    bytes(row["entry"].get(key)),
                    bytes(row["snapshot_peak"].get(key)),
                    bytes(row["end"].get(key)),
                ])
            });
            frame.render_widget(
                Table::new(
                    rows,
                    [
                        Constraint::Percentage(34),
                        Constraint::Percentage(22),
                        Constraint::Percentage(22),
                        Constraint::Percentage(22),
                    ],
                )
                .header(Row::new(vec!["Metric", "Entry", "Own peak", "End"]))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!("{title}: {name}")),
                ),
                panels[0],
            );
        } else {
            let score = row["median_score_change_percent"]
                .as_f64()
                .map_or_else(|| "unavailable".into(), |v| format!("{v:+.2}%"));
            let rows = vec![
                Row::new(vec![
                    "Private peak".into(),
                    change(row, "private_peak_change_percent"),
                ]),
                Row::new(vec![
                    "Working-set peak".into(),
                    change(row, "working_set_peak_change_percent"),
                ]),
                Row::new(vec![
                    "End private".into(),
                    change(row, "end_private_change_percent"),
                ]),
                Row::new(vec![
                    "Sampled CPU".into(),
                    change(row, "sampled_cpu_change_percent"),
                ]),
                Row::new(vec!["Score (higher better)".into(), score]),
            ];
            frame.render_widget(
                Table::new(
                    rows,
                    [Constraint::Percentage(60), Constraint::Percentage(40)],
                )
                .header(Row::new(vec!["Metric", "Median paired change"]))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!("{title}: {name}")),
                ),
                panels[0],
            );
        }
    } else {
        frame.render_widget(
            Paragraph::new("Report unavailable for this activity/view; press m to switch.")
                .block(Block::default().borders(Borders::ALL).title(title)),
            panels[0],
        );
    }
    let details = activity.details(state);
    let width = usize::from(panels[1].width.saturating_sub(2)).max(1);
    let lines = wrapped(&details, width);
    state.offset = state.offset.min(lines.len().saturating_sub(1));
    frame.render_widget(
        Paragraph::new(
            lines
                .iter()
                .skip(state.offset)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Exact fields | spaces, pairs, GC, gaps, scope"),
        ),
        panels[1],
    );
}

pub(super) fn next_activity_mode(state: &mut State) {
    state.activity_mode = (state.activity_mode + 1) % 2;
    state.offset = 0;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn activity_selection_updates_details_and_mode_without_losing_selection() {
        let activities = ActivityReports {
            composition: Some(
                serde_json::json!({"plans":{"A":{"snapshot_count":1},"B":{"snapshot_count":2}}}),
            ),
            comparison: None,
            names: vec!["A".into(), "B".into()],
        };
        let reports = Reports {
            phases: vec!["activities".into()],
            pages: vec![vec![vec![]; SECTIONS.len()]],
            target_pid: None,
            trace_complete: None,
            events_lost: None,
            required_pdb_failures: 0,
            stack_domains: vec![],
            stack_scan_truncated: false,
            lifecycle: None,
            projections: Projections::default(),
            skipped_oversized: vec![],
            activities,
        };
        let mut state = State::new(&reports);
        assert_eq!(state.section, 6);
        state.offset = 40;
        select_activity(&reports, &mut state, 1);
        assert_eq!(state.offset, 0);
        assert!(
            reports
                .activities
                .details(&state)
                .contains(&"snapshot_count: 2".to_owned())
        );
        next_activity_mode(&mut state);
        assert_eq!(state.activity_table.selected(), Some(1));
        assert!(reports.activities.details(&state)[0].contains("NOT zero"));
    }
}
