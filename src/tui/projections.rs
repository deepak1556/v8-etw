use super::*;

pub(super) fn projection_array<'a>(
    projections: &'a Projections,
    projection: &str,
    key: &str,
) -> Option<&'a Vec<Value>> {
    let value = match projection {
        "runtime" => projections.runtime.as_ref(),
        "suites" => projections.suites.as_ref(),
        _ => None,
    }?;
    value.get(key)?.as_array()
}

pub(super) fn draw_projection_health(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    reports: &Reports,
) {
    let Some(reader) = reports.projections.reader.as_ref() else {
        return;
    };
    let [cards, coverage, notes] = Layout::vertical([
        Constraint::Length(7),
        Constraint::Length(7),
        Constraint::Min(1),
    ])
    .areas(area);
    let card_areas: [ratatui::layout::Rect; 3] = Layout::horizontal([
        Constraint::Percentage(34),
        Constraint::Percentage(33),
        Constraint::Percentage(33),
    ])
    .areas(cards);
    let elapsed = reader
        .get("decode_elapsed_ms")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let selected = reader
        .get("selected_events")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let rate = selected
        .saturating_mul(1000)
        .checked_div(elapsed)
        .unwrap_or(0);
    let cards = [
        (
            "Decode",
            vec![
                format!("Events: {}", display(reader.get("total_events"))),
                format!("Selected: {}", display(reader.get("selected_events"))),
                format!("Rate: {rate} events/s"),
                format!("Elapsed: {:.1} s", elapsed as f64 / 1000.0),
            ],
        ),
        (
            "Transport",
            vec![
                format!("Events lost: {}", display(reader.pointer("/losses/events"))),
                format!(
                    "Buffers lost: {}",
                    display(reader.pointer("/losses/buffers"))
                ),
                format!("Lifecycle: {}", display(reader.get("lifetime_complete"))),
                format!("Schemas: {}", display(reader.get("schema_queries"))),
            ],
        ),
        (
            "Symbols",
            vec![
                format!("Frames: {}", display(reader.get("frame_occurrences"))),
                format!(
                    "Elapsed: {:.1} s",
                    reader
                        .get("symbol_attribution_ms")
                        .and_then(Value::as_u64)
                        .unwrap_or(0) as f64
                        / 1000.0
                ),
                format!("PDB: {}", display(reader.pointer("/frame_coverage/pdb"))),
                format!("JIT: {}", display(reader.pointer("/frame_coverage/jit"))),
            ],
        ),
    ];
    for (index, (title, lines)) in cards.into_iter().enumerate() {
        frame.render_widget(
            Paragraph::new(lines.join("\n")).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Span::styled(title, Style::default().fg(Color::Cyan))),
            ),
            card_areas[index],
        );
    }
    let frame_coverage = reader.get("frame_coverage").and_then(Value::as_object);
    let total_coverage: u64 = frame_coverage
        .into_iter()
        .flatten()
        .filter_map(|(_, value)| value.as_u64())
        .sum();
    let resolved = ["pdb", "jit", "module_only"]
        .iter()
        .filter_map(|key| frame_coverage?.get(*key)?.as_u64())
        .sum::<u64>();
    let ratio = if total_coverage == 0 {
        0.0
    } else {
        resolved as f64 / total_coverage as f64
    };
    frame.render_widget(
        Gauge::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Resolved/module-attributed frame occurrences"),
            )
            .ratio(ratio.clamp(0.0, 1.0))
            .gauge_style(Style::default().fg(Color::Green))
            .label(format!("{:.2}%", ratio * 100.0)),
        coverage,
    );
    let mut lines = vec![Line::from(Span::styled(
        "Canonical inputs",
        Style::default().fg(Color::Yellow),
    ))];
    lines.extend(
        reports
            .skipped_oversized
            .iter()
            .map(|message| Line::from(Span::styled(message, Style::default().fg(Color::Yellow)))),
    );
    lines.push(Line::from(Span::styled(
        "Projection sources",
        Style::default().fg(Color::Yellow),
    )));
    lines.extend(reports.projections.sources.iter().map(|source| {
        let path = Path::new(source);
        let compact = match (path.parent(), path.file_name()) {
            (Some(parent), Some(file)) => format!(
                "{}\\{}",
                parent
                    .file_name()
                    .map_or_else(|| "?".into(), |name| name.to_string_lossy()),
                file.to_string_lossy()
            ),
            _ => source.clone(),
        };
        Line::from(compact)
    }));
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Evidence and limits"),
        ),
        notes,
    );
}

pub(super) fn draw_projection_layers(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    reports: &Reports,
    state: &mut State,
) {
    if state.projection_layers_mode == 1
        && let Some(suites) = projection_array(&reports.projections, "suites", "ranked_suite_costs")
    {
        let selected = state
            .projection_suite_table
            .selected()
            .unwrap_or(0)
            .min(suites.len().saturating_sub(1));
        state.projection_suite_table.select(Some(selected));
        let rows = suites.iter().map(|suite| {
            Row::new(vec![
                display(suite.get("suite")),
                display(suite.get("observed_iterations")),
                format_bytes(
                    suite
                        .get("median_allocation_traffic_bytes")
                        .and_then(Value::as_f64)
                        .unwrap_or(0.0) as u64,
                ),
                format!(
                    "{:.0}",
                    suite
                        .get("median_allocation_count")
                        .and_then(Value::as_f64)
                        .unwrap_or(0.0)
                ),
                format_bytes(
                    suite
                        .get("median_cppgc_after_bytes")
                        .and_then(Value::as_f64)
                        .unwrap_or(0.0) as u64,
                ),
            ])
        });
        frame.render_stateful_widget(
            Table::new(
                rows,
                [
                    Constraint::Min(24),
                    Constraint::Length(8),
                    Constraint::Length(16),
                    Constraint::Length(13),
                    Constraint::Length(14),
                ],
            )
            .header(
                Row::new([
                    "Suite",
                    "Iters",
                    "Alloc traffic",
                    "Alloc count",
                    "cppgc after",
                ])
                .style(
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
                Block::default().borders(Borders::ALL).title(
                    "Suite demand [m: iteration trends] — prepared is after suite preparation",
                ),
            ),
            area,
            &mut state.projection_suite_table,
        );
        return;
    }
    let Some(iterations) = projection_array(&reports.projections, "runtime", "iteration_memory")
    else {
        return;
    };
    let [chart_area, table_area] =
        Layout::vertical([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(area);
    let series = [
        ("V8 used", "v8_used_bytes", Color::Cyan),
        ("cppgc used", "cppgc_used_bytes", Color::Green),
        (
            "native estimate",
            "native_estimated_live_bytes",
            Color::Magenta,
        ),
    ];
    let datasets = series
        .iter()
        .map(|(name, key, color)| {
            let points = iterations
                .iter()
                .enumerate()
                .map(|(index, row)| {
                    (
                        index as f64 + 1.0,
                        row.get(*key).and_then(Value::as_u64).unwrap_or(0) as f64,
                    )
                })
                .collect::<Vec<_>>();
            (*name, *color, points)
        })
        .collect::<Vec<_>>();
    let max_y = datasets
        .iter()
        .flat_map(|(_, _, points)| points.iter().map(|(_, value)| *value))
        .fold(1.0f64, f64::max);
    let chart_sets = datasets
        .iter()
        .map(|(name, color, points)| {
            Dataset::default()
                .name(*name)
                .marker(Marker::Braille)
                .graph_type(GraphType::Line)
                .style(Style::default().fg(*color))
                .data(points)
        })
        .collect();
    frame.render_widget(
        Chart::new(chart_sets)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Iteration memory lenses — non-additive"),
            )
            .x_axis(
                Axis::default()
                    .bounds([1.0, iterations.len().max(1) as f64])
                    .labels(vec![
                        Line::from("1"),
                        Line::from(iterations.len().to_string()),
                    ]),
            )
            .y_axis(Axis::default().bounds([0.0, max_y]).labels(vec![
                Line::from("0"),
                Line::from(format_bytes(max_y as u64)),
            ])),
        chart_area,
    );
    let rows = iterations.iter().enumerate().map(|(index, row)| {
        Row::new(vec![
            (index + 1).to_string(),
            display(row.get("phase")),
            format_bytes(
                row.get("v8_used_bytes")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            ),
            format_bytes(
                row.get("cppgc_used_bytes")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            ),
            format_bytes(
                row.get("native_estimated_live_bytes")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            ),
        ])
    });
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(6),
                Constraint::Min(20),
                Constraint::Length(14),
                Constraint::Length(14),
                Constraint::Length(16),
            ],
        )
        .header(
            Row::new(["Iter", "Phase", "V8 used", "cppgc used", "Native estimate"]).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Iteration census [m: suite demand] — never grand sum lenses"),
        ),
        table_area,
    );
}

pub(super) fn draw_projection_types(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    reports: &Reports,
    state: &mut State,
) {
    let Some(types) = projection_array(
        &reports.projections,
        "runtime",
        "cppgc_types_by_median_iteration_footprint",
    ) else {
        return;
    };
    let selected = state
        .projection_types_table
        .selected()
        .unwrap_or(0)
        .min(types.len().saturating_sub(1));
    state.projection_types_table.select(Some(selected));
    let split: [ratatui::layout::Rect; 2] =
        Layout::horizontal([Constraint::Percentage(72), Constraint::Percentage(28)]).areas(area);
    let rows = types.iter().map(|row| {
        Row::new(vec![
            display(row.get("type")),
            display(row.get("present_iterations")),
            format_bytes(
                row.get("median_allocated_bytes")
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0) as u64,
            ),
            format_bytes(
                row.get("min_allocated_bytes")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            ),
            format_bytes(
                row.get("max_allocated_bytes")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            ),
            format!(
                "{:.0}",
                row.get("median_object_count")
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0)
            ),
        ])
    });
    frame.render_stateful_widget(
        Table::new(
            rows,
            [
                Constraint::Min(28),
                Constraint::Length(7),
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(10),
            ],
        )
        .header(
            Row::new(["Type", "Iters", "Median", "Min", "Max", "Objects"]).style(
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
                .title("cppgc runtime types — absent iterations count as zero"),
        ),
        split[0],
        &mut state.projection_types_table,
    );
    let row = &types[selected];
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                display(row.get("type")),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(format!(
                "Present: {} / 10 iterations",
                display(row.get("present_iterations"))
            )),
            Line::from(format!(
                "Median footprint: {}",
                format_bytes(
                    row.get("median_allocated_bytes")
                        .and_then(Value::as_f64)
                        .unwrap_or(0.0) as u64
                )
            )),
            Line::from(format!(
                "Range: {} – {}",
                format_bytes(
                    row.get("min_allocated_bytes")
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                ),
                format_bytes(
                    row.get("max_allocated_bytes")
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                )
            )),
            Line::from(""),
            Line::from("Snapshot footprint may include dead-but-unswept objects."),
            Line::from("This ranks runtime representation cost, not application ownership."),
        ])
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Selected type"),
        ),
        split[1],
    );
}

pub(super) fn draw_projection_allocator(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    reports: &Reports,
    state: &mut State,
) {
    let Some(rows) = projection_array(
        &reports.projections,
        "runtime",
        "largest_bucket_slack_observations",
    ) else {
        return;
    };
    let selected = state
        .projection_allocator_table
        .selected()
        .unwrap_or(0)
        .min(rows.len().saturating_sub(1));
    state.projection_allocator_table.select(Some(selected));
    let table_rows = rows.iter().map(|row| {
        Row::new(vec![
            display(row.get("phase")),
            display(row.get("root")),
            display(row.get("slot_bytes")),
            format_bytes(row.get("active_bytes").and_then(Value::as_u64).unwrap_or(0)),
            format_bytes(
                row.get("provisioned_bytes")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            ),
            format_bytes(
                row.get("provisioned_slack_bytes")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            ),
            display(row.get("empty_spans")),
        ])
    });
    frame.render_stateful_widget(
        Table::new(
            table_rows,
            [
                Constraint::Min(18),
                Constraint::Min(24),
                Constraint::Length(8),
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(7),
            ],
        )
        .header(
            Row::new([
                "Phase",
                "Root",
                "Slot",
                "Active",
                "Provisioned",
                "Slack",
                "Empty",
            ])
            .style(
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
                .title("Largest allocator slack observations — slack is not proven reclaimable"),
        ),
        area,
        &mut state.projection_allocator_table,
    );
}

pub(super) fn draw_projection_lifecycle(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    reports: &Reports,
    state: &mut State,
) {
    let Some(runtime) = reports.projections.runtime.as_ref() else {
        return;
    };
    let heaps = runtime
        .get("lifetime_heaps")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let large_heaps = reports
        .projections
        .large
        .as_ref()
        .and_then(|value| value.get("heaps"))
        .and_then(Value::as_object);
    let [summary, body] = Layout::vertical([Constraint::Length(7), Constraint::Min(1)]).areas(area);
    let heap = heaps.first();
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    "Projection mode ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("— detailed object streams exceed the interactive limit"),
            ]),
            Line::from(format!(
                "Heap {}  complete={}  major GCs={}",
                display(heap.and_then(|value| value.get("heap_id"))),
                display(heap.and_then(|value| value.get("complete"))),
                display(heap.and_then(|value| value.get("completed_major_gcs")))
            )),
            Line::from(format!(
                "Live: {} objects / {}",
                display(heap.and_then(|value| value.get("live_objects"))),
                format_bytes(
                    heap.and_then(|value| value.get("live_bytes"))
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                )
            )),
            Line::from(
                "Large allocations are exact cppgc capacities, not RSS and not proven leaks.",
            ),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Lifecycle projection"),
        ),
        summary,
    );
    let large = large_heaps
        .into_iter()
        .flatten()
        .flat_map(|(_, heap)| {
            heap.get("largest_allocations")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .collect::<Vec<_>>();
    if large.is_empty() {
        frame.render_widget(
            Paragraph::new("No large-allocation projection available.")
                .block(Block::default().borders(Borders::ALL)),
            body,
        );
        return;
    }
    let selected = state
        .projection_large_table
        .selected()
        .unwrap_or(0)
        .min(large.len() - 1);
    state.projection_large_table.select(Some(selected));
    let [table_area, detail_area]: [ratatui::layout::Rect; 2] = if body.width >= 100 {
        Layout::horizontal([Constraint::Percentage(68), Constraint::Percentage(32)]).areas(body)
    } else {
        Layout::vertical([Constraint::Percentage(65), Constraint::Percentage(35)]).areas(body)
    };
    let rows = large.iter().map(|row| {
        Row::new(vec![
            display(row.get("allocation_id")),
            display(row.get("type_name")),
            format_bytes(row.get("bytes").and_then(Value::as_u64).unwrap_or(0)),
            display(row.get("gc_info")),
            display(row.get("freed_at")),
        ])
    });
    frame.render_stateful_widget(
        Table::new(
            rows,
            [
                Constraint::Length(12),
                Constraint::Min(28),
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(14),
            ],
        )
        .header(
            Row::new(["Stable ID", "Type", "Capacity", "GCInfo", "Freed at"]).style(
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
                .title("Largest exact cppgc allocations"),
        ),
        table_area,
        &mut state.projection_large_table,
    );
    let row = large[selected];
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    format!("ID {}", display(row.get("allocation_id"))),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(
                    "  {}",
                    format_bytes(row.get("bytes").and_then(Value::as_u64).unwrap_or(0))
                )),
            ]),
            Line::from(display(row.get("type_name"))),
            Line::from(format!("GCInfo: {}", display(row.get("gc_info")))),
            Line::from(format!(
                "Allocated at: {}",
                display(row.get("allocated_at"))
            )),
            Line::from(format!("Freed at: {}", display(row.get("freed_at")))),
            Line::from(""),
            Line::from("Exact cppgc allocated capacity."),
            Line::from("Not RSS/private commit and not a proven leak."),
        ])
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Selected large allocation"),
        ),
        detail_area,
    );
}

pub(super) fn projected_large_allocation_count(reports: &Reports) -> usize {
    reports
        .projections
        .large
        .as_ref()
        .and_then(|value| value.get("heaps"))
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(_, heap)| heap.get("largest_allocations").and_then(Value::as_array))
        .map(Vec::len)
        .sum()
}

pub(super) fn projection_lifecycle_active(reports: &Reports, state: &State) -> bool {
    state.section == 5 && reports.lifecycle.is_none() && reports.projections.runtime.is_some()
}

pub(super) fn select_projected_large_allocation(
    reports: &Reports,
    state: &mut State,
    movement: isize,
) {
    let last = projected_large_allocation_count(reports).saturating_sub(1);
    let selected = state.projection_large_table.selected().unwrap_or(0);
    let next = if movement < 0 {
        selected.saturating_sub(movement.unsigned_abs())
    } else {
        selected.saturating_add(movement as usize).min(last)
    };
    state.projection_large_table.select(Some(next));
}
