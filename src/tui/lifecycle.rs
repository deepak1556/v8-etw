use super::*;

pub(super) fn life_kind(kind: &str) -> &'static str {
    match kind {
        "2" => "seed",
        "4" => "alloc",
        "5" => "free",
        "6" => "move",
        "7" => "resize",
        _ => "event",
    }
}

pub(super) fn object_timeline(lifecycle: &Lifecycle, object: &LifeObject) -> Vec<Line<'static>> {
    let start = object.events.first().map_or(0, |event| event.sequence);
    let end = object
        .events
        .last()
        .map_or(lifecycle.capture_end_sequence, |event| {
            if event.kind == "5" {
                event.sequence
            } else {
                lifecycle.capture_end_sequence
            }
        });
    let mut entries = object
        .events
        .iter()
        .map(|event| {
            (
                event.sequence,
                format!(
                    "seq {:>4} {:<6} {} (epoch {})",
                    event.sequence,
                    life_kind(&event.kind),
                    format_bytes(event.bytes),
                    event.gc_epoch
                ),
            )
        })
        .collect::<Vec<_>>();
    entries.extend(
        lifecycle
            .major_sequences
            .iter()
            .filter(|(sequence, _)| *sequence > start && *sequence < end)
            .map(|(sequence, epoch)| {
                (*sequence, format!("seq {sequence:>4} major GC {epoch} end"))
            }),
    );
    entries.sort_by_key(|entry| entry.0);
    entries
        .into_iter()
        .map(|(_, text)| Line::from(text))
        .collect()
}

pub(super) fn survived_major_gcs(lifecycle: &Lifecycle, object: &LifeObject) -> usize {
    let start = object.events.first().map_or(0, |event| event.sequence);
    let end = object
        .events
        .last()
        .map_or(lifecycle.capture_end_sequence, |event| {
            if event.kind == "5" {
                event.sequence
            } else {
                lifecycle.capture_end_sequence
            }
        });
    lifecycle
        .major_sequences
        .iter()
        .filter(|(sequence, _)| *sequence > start && *sequence < end)
        .count()
}

pub(super) fn object_lifetime_graph(
    lifecycle: &Lifecycle,
    object: &LifeObject,
    width: usize,
) -> Vec<Line<'static>> {
    let width = width.clamp(24, 120);
    let start = lifecycle.capture_start_sequence;
    let end = lifecycle.capture_end_sequence.max(start + 1);
    let position = |sequence: u64| {
        let offset = sequence.saturating_sub(start);
        let range = end - start;
        ((offset as u128 * (width - 1) as u128) / range as u128) as usize
    };
    let mut track = vec!['·'; width];
    let object_start = object.events.first().map_or(start, |event| event.sequence);
    let object_end = object.events.last().map_or(end, |event| {
        if event.kind == "5" {
            event.sequence
        } else {
            end
        }
    });
    for cell in track
        .iter_mut()
        .take(position(object_end) + 1)
        .skip(position(object_start))
    {
        *cell = '━';
    }
    track[0] = '├';
    track[width - 1] = '┤';
    for (sequence, _) in &lifecycle.major_sequences {
        track[position(*sequence)] = '◆';
    }
    for event in &object.events {
        track[position(event.sequence)] = match event.kind.as_str() {
            "2" => 'S',
            "4" => 'A',
            "5" => '×',
            "6" => 'M',
            "7" => 'R',
            _ => '•',
        };
    }
    let freed = object.events.last().is_some_and(|event| event.kind == "5");
    let status = if freed {
        format!(
            "freed after {} completed major GC(s)",
            survived_major_gcs(lifecycle, object)
        )
    } else {
        format!(
            "live at capture end after {} completed major GC(s)",
            survived_major_gcs(lifecycle, object)
        )
    };
    vec![
        Line::from(format!(
            "capture seq {} {} {}",
            start,
            track.into_iter().collect::<String>(),
            end
        )),
        Line::from(format!(
            "object {}: {}  {}  {status}",
            object.id,
            if object.seeded { "seeded" } else { "allocated" },
            format_bytes(object.bytes)
        )),
        Line::from("S seed  A allocation  ◆ completed major GC  M move  R resize  × free"),
    ]
}

pub(super) fn object_freed(object: &LifeObject) -> bool {
    object.events.last().is_some_and(|event| event.kind == "5")
}

pub(super) fn object_live_at(object: &LifeObject, sequence: u64) -> bool {
    let Some(first) = object.events.first() else {
        return false;
    };
    if first.sequence > sequence {
        return false;
    }
    !object
        .events
        .iter()
        .any(|event| event.kind == "5" && event.sequence <= sequence)
}

pub(super) fn object_cohort(lifecycle: &Lifecycle, object: &LifeObject) -> String {
    if object.seeded {
        return "Seeded before capture".into();
    }
    let birth = object.events.first().map_or(0, |event| event.sequence);
    let completed = lifecycle
        .major_sequences
        .iter()
        .filter(|(sequence, _)| *sequence < birth)
        .count();
    if completed == 0 {
        "Born before major GC 1".into()
    } else if completed < lifecycle.major_sequences.len() {
        format!("Born after GC {completed}")
    } else {
        format!("Born after GC {}", lifecycle.major_sequences.len())
    }
}

pub(super) fn population_metric(lifecycle: &Lifecycle, objects: &[usize], metric: usize) -> u64 {
    match metric {
        0 => objects
            .iter()
            .filter_map(|index| lifecycle.objects.get(*index))
            .filter(|object| !object_freed(object))
            .map(|object| object.bytes)
            .sum(),
        1 => objects
            .iter()
            .filter_map(|index| lifecycle.objects.get(*index))
            .filter(|object| !object_freed(object))
            .count() as u64,
        2 => objects
            .iter()
            .filter_map(|index| lifecycle.objects.get(*index))
            .filter(|object| !object.seeded)
            .map(|object| object.bytes)
            .sum(),
        3 => objects
            .iter()
            .filter_map(|index| lifecycle.objects.get(*index))
            .filter(|object| object_freed(object))
            .map(|object| object.bytes)
            .sum(),
        _ => objects
            .iter()
            .filter_map(|index| lifecycle.objects.get(*index))
            .map(|object| {
                object
                    .bytes
                    .saturating_mul(survived_major_gcs(lifecycle, object) as u64)
            })
            .sum(),
    }
}

pub(super) fn population_rows(lifecycle: &Lifecycle, state: &State) -> Vec<PopulationRow> {
    let mut by_type = BTreeMap::<u64, Vec<usize>>::new();
    for (index, object) in lifecycle.objects.iter().enumerate() {
        by_type.entry(object.gc_info).or_default().push(index);
    }
    let mut types = by_type.into_iter().collect::<Vec<_>>();
    types.sort_by(|a, b| {
        population_metric(lifecycle, &b.1, state.life_metric)
            .cmp(&population_metric(lifecycle, &a.1, state.life_metric))
            .then_with(|| a.0.cmp(&b.0))
    });
    let mut rows = Vec::new();
    for (gc_info, indices) in types {
        let type_id = format!("type:{gc_info}");
        rows.push(PopulationRow {
            id: type_id.clone(),
            depth: 0,
            gc_info,
            label: lifecycle
                .type_names
                .get(&gc_info)
                .cloned()
                .unwrap_or_else(|| format!("GCInfo {gc_info}")),
            object_indices: indices.clone(),
            expandable: true,
        });
        if !state.life_profile_expanded.contains(&type_id) {
            continue;
        }
        let mut cohorts = BTreeMap::<String, Vec<usize>>::new();
        for index in &indices {
            let object = &lifecycle.objects[*index];
            cohorts
                .entry(object_cohort(lifecycle, object))
                .or_default()
                .push(*index);
        }
        for (cohort, cohort_indices) in cohorts {
            let cohort_id = format!("{type_id}\u{1f}{cohort}");
            rows.push(PopulationRow {
                id: cohort_id.clone(),
                depth: 1,
                gc_info,
                label: cohort,
                object_indices: cohort_indices.clone(),
                expandable: true,
            });
            if !state.life_profile_expanded.contains(&cohort_id) {
                continue;
            }
            for index in cohort_indices {
                let object = &lifecycle.objects[index];
                rows.push(PopulationRow {
                    id: format!("{cohort_id}\u{1f}{}", object.id),
                    depth: 2,
                    gc_info,
                    label: format!("Object {}", object.id),
                    object_indices: vec![index],
                    expandable: false,
                });
            }
        }
    }
    rows
}

pub(super) fn lifecycle_boundaries(lifecycle: &Lifecycle) -> Vec<(String, u64)> {
    let seed = if lifecycle.inventory_end_sequence == 0 {
        lifecycle.capture_start_sequence
    } else {
        lifecycle.inventory_end_sequence
    };
    let mut boundaries = vec![("Seed".into(), seed)];
    boundaries.extend(
        lifecycle
            .major_sequences
            .iter()
            .map(|(sequence, epoch)| (format!("GC {epoch}"), *sequence)),
    );
    if boundaries
        .last()
        .is_none_or(|(_, sequence)| *sequence != lifecycle.capture_end_sequence)
    {
        boundaries.push(("End".into(), lifecycle.capture_end_sequence));
    }
    boundaries
}

pub(super) fn live_bytes_at(lifecycle: &Lifecycle, sequence: u64, gc_info: Option<u64>) -> u64 {
    lifecycle
        .objects
        .iter()
        .filter(|object| gc_info.is_none_or(|value| object.gc_info == value))
        .filter(|object| object_live_at(object, sequence))
        .map(|object| object.bytes)
        .sum()
}

pub(super) fn gc_intervals(lifecycle: &Lifecycle, scope: Option<u64>) -> Vec<GcInterval> {
    let boundaries = lifecycle_boundaries(lifecycle);
    boundaries
        .windows(2)
        .map(|window| {
            let (before_name, before_sequence) = &window[0];
            let (after_name, after_sequence) = &window[1];
            let mut allocated_bytes = 0u64;
            let mut freed_bytes = 0u64;
            let mut by_type = BTreeMap::<u64, (u64, u64)>::new();
            for object in &lifecycle.objects {
                if scope.is_some_and(|value| object.gc_info != value) {
                    continue;
                }
                let before_live = object_live_at(object, *before_sequence);
                let after_live = object_live_at(object, *after_sequence);
                let entry = by_type.entry(object.gc_info).or_default();
                if before_live {
                    entry.0 += object.bytes;
                }
                if after_live {
                    entry.1 += object.bytes;
                }
                if !object.seeded
                    && object.events.first().is_some_and(|event| {
                        event.sequence > *before_sequence && event.sequence <= *after_sequence
                    })
                {
                    allocated_bytes += object.bytes;
                }
                if object.events.iter().any(|event| {
                    event.kind == "5"
                        && event.sequence > *before_sequence
                        && event.sequence <= *after_sequence
                }) {
                    freed_bytes += object.bytes;
                }
            }
            let mut contributors = by_type
                .into_iter()
                .map(|(gc_info, (before, after))| TypeContribution {
                    gc_info,
                    delta_bytes: after as i64 - before as i64,
                    after_bytes: after,
                })
                .filter(|row| row.delta_bytes != 0 || row.after_bytes != 0)
                .collect::<Vec<_>>();
            contributors.sort_by(|a, b| {
                b.delta_bytes
                    .unsigned_abs()
                    .cmp(&a.delta_bytes.unsigned_abs())
                    .then_with(|| b.after_bytes.cmp(&a.after_bytes))
            });
            GcInterval {
                label: format!("{before_name} → {after_name}"),
                before_bytes: live_bytes_at(lifecycle, *before_sequence, scope),
                allocated_bytes,
                freed_bytes,
                after_bytes: live_bytes_at(lifecycle, *after_sequence, scope),
                contributors,
            }
        })
        .collect()
}

pub(super) fn draw_object_inspector(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    reports: &Reports,
    state: &mut State,
) {
    let Some(lifecycle) = &reports.lifecycle else {
        frame.render_widget(
            Paragraph::new(
                "Lifecycle unavailable: cppgc-history.json or cppgc-lifetimes.jsonl missing.",
            )
            .block(Block::default().borders(Borders::ALL)),
            area,
        );
        return;
    };
    let object_indices = lifecycle
        .objects
        .iter()
        .enumerate()
        .filter(|(_, object)| {
            state
                .life_selected_type
                .is_none_or(|gc_info| object.gc_info == gc_info)
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if object_indices.is_empty() {
        frame.render_widget(
            Paragraph::new("No stable allocation IDs match the selected type.")
                .block(Block::default().borders(Borders::ALL).title("Lifecycle")),
            area,
        );
        return;
    }
    let selected = state
        .life_table
        .selected()
        .unwrap_or(0)
        .min(object_indices.len() - 1);
    state.life_table.select(Some(selected));
    let object = &lifecycle.objects[object_indices[selected]];
    let complete = if lifecycle.complete {
        Span::styled("[CAPTURE COMPLETE]", Style::default().fg(Color::Green))
    } else {
        Span::styled("[CAPTURE INCOMPLETE]", Style::default().fg(Color::Yellow))
    };
    let summary = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" {} ", lifecycle.heap_id),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        complete,
        Span::raw(format!(
            "  {} displayed / {} indexed objects  {} major GCs",
            object_indices.len(),
            lifecycle.objects.len(),
            lifecycle.major_live_bytes.len()
        )),
    ]))
    .block(Block::default().borders(Borders::ALL).title("Object scope"));
    let [summary_area, chart_area, body] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(5),
        Constraint::Min(1),
    ])
    .areas(area);
    frame.render_widget(summary, summary_area);
    frame.render_widget(
        Paragraph::new(object_lifetime_graph(
            lifecycle,
            object,
            usize::from(chart_area.width.saturating_sub(4)),
        ))
        .style(Style::default().fg(Color::Cyan))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Selected object lifetime across the capture"),
        ),
        chart_area,
    );
    let split: [ratatui::layout::Rect; 2] = if body.width >= 100 {
        Layout::horizontal([Constraint::Percentage(62), Constraint::Percentage(38)]).areas(body)
    } else {
        Layout::vertical([Constraint::Percentage(60), Constraint::Percentage(40)]).areas(body)
    };
    let object_rows = object_indices.iter().map(|index| {
        let object = &lifecycle.objects[*index];
        let name = lifecycle
            .type_names
            .get(&object.gc_info)
            .map(String::as_str)
            .unwrap_or("<type name unavailable>");
        let status = if object.events.last().is_some_and(|event| event.kind == "5") {
            "freed"
        } else {
            "live/end"
        };
        Row::new(vec![
            object.id.to_string(),
            name.to_owned(),
            format_bytes(object.bytes),
            if object.seeded { "seed" } else { "new" }.into(),
            status.into(),
        ])
    });
    let table = Table::new(
        object_rows,
        [
            Constraint::Length(9),
            Constraint::Min(24),
            Constraint::Length(10),
            Constraint::Length(7),
            Constraint::Length(9),
        ],
    )
    .header(
        Row::new(["Stable ID", "Type", "Bytes", "Origin", "Status"]).style(
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
            .title("Object Inspector (retention candidates are not proven leaks)"),
    );
    frame.render_stateful_widget(table, split[0], &mut state.life_table);
    let type_name = lifecycle
        .type_names
        .get(&object.gc_info)
        .map(String::as_str)
        .unwrap_or("<type name unavailable>");
    let mut details = vec![
        Line::from(vec![
            Span::styled(
                format!("ID {}", object.id),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "  {}  GCInfo {}",
                format_bytes(object.bytes),
                object.gc_info
            )),
        ]),
        Line::from(type_name.to_owned()),
        Line::from(if object.seeded {
            "Pre-capture seed: requested payload decomposition unknown."
        } else {
            "New object: requested/header/padding may be exact when recorded."
        }),
        Line::from(vec![
            Span::styled("Retention: ", Style::default().fg(Color::Yellow)),
            Span::raw(format!(
                "survived {} completed major GC(s).",
                survived_major_gcs(lifecycle, object)
            )),
        ]),
        Line::from(
            if object.events.last().is_some_and(|event| event.kind == "5") {
                "Freed during capture; not retained at capture end."
            } else {
                "Live at capture end; investigate growth and intended roots."
            },
        ),
        Line::from(vec![
            Span::styled("Retainers: ", Style::default().fg(Color::Yellow)),
            Span::raw("not captured (no reference edges)."),
        ]),
        Line::from(
            if reports.stack_domains.iter().any(|domain| {
                domain.exact
                    && domain
                        .root
                        .allocation
                        .allocation_ids
                        .contains_key(&object.id)
            }) {
                Span::styled(
                    "Allocation stack is origin, not retainer. [c] open origin",
                    Style::default().fg(Color::Cyan),
                )
            } else {
                Span::styled(
                    "Origin unavailable: allocation occurred before capture or stack was not observed.",
                    Style::default().fg(Color::Yellow),
                )
            },
        ),
        Line::from(Span::styled(
            "Event timeline",
            Style::default().fg(Color::Yellow),
        )),
    ];
    details.extend(object_timeline(lifecycle, object));
    frame.render_widget(
        Paragraph::new(details).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Selection details"),
        ),
        split[1],
    );
}

pub(super) fn lifecycle_metric_name(metric: usize) -> &'static str {
    match metric {
        0 => "live@end bytes",
        1 => "live@end objects",
        2 => "new allocated bytes",
        3 => "freed bytes",
        _ => "survivor byte-GCs",
    }
}

pub(super) fn draw_retention_profile(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    reports: &Reports,
    state: &mut State,
) {
    let Some(lifecycle) = &reports.lifecycle else {
        frame.render_widget(Paragraph::new("Lifecycle unavailable."), area);
        return;
    };
    let rows = population_rows(lifecycle, state);
    if rows.is_empty() {
        frame.render_widget(Paragraph::new("No lifecycle populations."), area);
        return;
    }
    let selected = state
        .life_profile_table
        .selected()
        .unwrap_or(0)
        .min(rows.len() - 1);
    state.life_profile_table.select(Some(selected));
    let population = &rows[selected];
    state.life_selected_type = Some(population.gc_info);
    let split: [ratatui::layout::Rect; 2] = if area.width >= 100 {
        Layout::horizontal([Constraint::Percentage(67), Constraint::Percentage(33)]).areas(area)
    } else {
        Layout::vertical([Constraint::Percentage(62), Constraint::Percentage(38)]).areas(area)
    };
    let table_rows = rows.iter().map(|row| {
        let marker = if !row.expandable {
            "•"
        } else if state.life_profile_expanded.contains(&row.id) {
            "▼"
        } else {
            "▶"
        };
        let objects = row
            .object_indices
            .iter()
            .filter(|index| !object_freed(&lifecycle.objects[**index]))
            .count();
        let freed = row
            .object_indices
            .iter()
            .filter(|index| object_freed(&lifecycle.objects[**index]))
            .count();
        let oldest = row
            .object_indices
            .iter()
            .map(|index| survived_major_gcs(lifecycle, &lifecycle.objects[*index]))
            .max()
            .unwrap_or(0);
        Row::new(vec![
            format_bytes(population_metric(
                lifecycle,
                &row.object_indices,
                state.life_metric,
            )),
            objects.to_string(),
            freed.to_string(),
            oldest.to_string(),
            format!("{}{} {}", "  ".repeat(row.depth), marker, row.label),
        ])
    });
    let table = Table::new(
        table_rows,
        [
            Constraint::Length(12),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(5),
            Constraint::Min(24),
        ],
    )
    .header(
        Row::new(["Metric", "Live", "Freed", "Age", "Type → cohort → object"]).style(
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
    .block(Block::default().borders(Borders::ALL).title(format!(
        "Retention profile — {}",
        lifecycle_metric_name(state.life_metric)
    )));
    frame.render_stateful_widget(table, split[0], &mut state.life_profile_table);
    let live_objects = population
        .object_indices
        .iter()
        .filter(|index| !object_freed(&lifecycle.objects[**index]))
        .count();
    let freed_objects = population.object_indices.len() - live_objects;
    let seeded = population
        .object_indices
        .iter()
        .filter(|index| lifecycle.objects[**index].seeded)
        .count();
    let origin_count = population
        .object_indices
        .iter()
        .filter(|index| {
            let id = lifecycle.objects[**index].id;
            reports.stack_domains.iter().any(|domain| {
                domain.exact && domain.root.allocation.allocation_ids.contains_key(&id)
            })
        })
        .count();
    let boundaries = lifecycle_boundaries(lifecycle);
    let trend = boundaries
        .iter()
        .map(|(_, sequence)| {
            format_bytes(
                population
                    .object_indices
                    .iter()
                    .filter(|index| object_live_at(&lifecycle.objects[**index], *sequence))
                    .map(|index| lifecycle.objects[*index].bytes)
                    .sum(),
            )
        })
        .collect::<Vec<_>>()
        .join(" → ");
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                &population.label,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(format!(
                "Population: {} object(s), {}",
                population.object_indices.len(),
                format_bytes(
                    population
                        .object_indices
                        .iter()
                        .map(|index| lifecycle.objects[*index].bytes)
                        .sum()
                )
            )),
            Line::from(format!(
                "Fates: {live_objects} live@end, {freed_objects} freed"
            )),
            Line::from(format!(
                "Origin: {seeded} seeded, {} new; {origin_count} exact stack(s)",
                population.object_indices.len() - seeded
            )),
            Line::from(format!("GC trend: {trend}")),
            Line::from(format!(
                "Capture final: {} objects / {}",
                lifecycle.live_objects,
                format_bytes(lifecycle.live_bytes)
            )),
            Line::from(format!(
                "Decomposition: header {}  known payload {}  known padding {}",
                lifecycle
                    .header_bytes
                    .map_or_else(|| "unknown".into(), format_bytes),
                format_bytes(lifecycle.known_payload_bytes),
                format_bytes(lifecycle.known_padding_bytes)
            )),
            Line::from(format!(
                "Unknown requested size: {} object(s)",
                lifecycle.unknown_requested_objects
            )),
            Line::from(""),
            Line::from(Span::styled(
                "Retention evidence",
                Style::default().fg(Color::Yellow),
            )),
            Line::from("Old populations merit investigation only when unintended and growing."),
            Line::from("Retainers are not captured; allocation origins are not retaining paths."),
            Line::from(""),
            Line::from("[t] GC Timeline scoped to this type"),
            Line::from("[o] Object Inspector for this type"),
        ])
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Selected population"),
        ),
        split[1],
    );
}

pub(super) fn draw_gc_timeline(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    reports: &Reports,
    state: &mut State,
) {
    let Some(lifecycle) = &reports.lifecycle else {
        frame.render_widget(Paragraph::new("Lifecycle unavailable."), area);
        return;
    };
    let boundaries = lifecycle_boundaries(lifecycle);
    let points = boundaries
        .iter()
        .enumerate()
        .map(|(index, (_, sequence))| {
            (
                index as f64,
                live_bytes_at(lifecycle, *sequence, state.life_selected_type) as f64,
            )
        })
        .collect::<Vec<_>>();
    let max_y = points
        .iter()
        .map(|(_, value)| *value)
        .fold(1.0f64, f64::max);
    let scope = state
        .life_selected_type
        .and_then(|gc_info| lifecycle.type_names.get(&gc_info))
        .map_or("all types", String::as_str);
    let [chart_area, body] =
        Layout::vertical([Constraint::Length(10), Constraint::Min(1)]).areas(area);
    let dataset = Dataset::default()
        .name("live bytes")
        .marker(Marker::Braille)
        .graph_type(GraphType::Line)
        .style(Style::default().fg(Color::Cyan))
        .data(&points);
    frame.render_widget(
        Chart::new(vec![dataset])
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!("GC Timeline — scope: {scope}")),
            )
            .x_axis(
                Axis::default()
                    .bounds([0.0, points.len().saturating_sub(1).max(1) as f64])
                    .labels(vec![
                        Line::from(
                            boundaries
                                .first()
                                .map_or("Seed", |(label, _)| label.as_str()),
                        ),
                        Line::from(boundaries.last().map_or("End", |(label, _)| label.as_str())),
                    ]),
            )
            .y_axis(Axis::default().bounds([0.0, max_y]).labels(vec![
                Line::from("0"),
                Line::from(format_bytes(max_y as u64)),
            ])),
        chart_area,
    );
    let intervals = gc_intervals(lifecycle, state.life_selected_type);
    if intervals.is_empty() {
        frame.render_widget(Paragraph::new("No completed GC intervals."), body);
        return;
    }
    let selected = state
        .life_timeline_table
        .selected()
        .unwrap_or(0)
        .min(intervals.len() - 1);
    state.life_timeline_table.select(Some(selected));
    let interval = &intervals[selected];
    let contributor_selected = state
        .life_contributor_table
        .selected()
        .unwrap_or(0)
        .min(interval.contributors.len().saturating_sub(1));
    state
        .life_contributor_table
        .select(Some(contributor_selected));
    let split: [ratatui::layout::Rect; 2] =
        Layout::horizontal([Constraint::Percentage(48), Constraint::Percentage(52)]).areas(body);
    let interval_rows = intervals.iter().map(|interval| {
        Row::new(vec![
            interval.label.clone(),
            format_bytes(interval.before_bytes),
            format!("+{}", format_bytes(interval.allocated_bytes)),
            format!("-{}", format_bytes(interval.freed_bytes)),
            format_bytes(interval.after_bytes),
        ])
    });
    let interval_table = Table::new(
        interval_rows,
        [
            Constraint::Min(15),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(10),
        ],
    )
    .header(
        Row::new(["Interval", "Before", "Alloc", "Free", "After"]).style(
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
            .border_style(if state.life_timeline_focus_contributors {
                Style::default()
            } else {
                Style::default().fg(Color::Cyan)
            })
            .title("GC intervals"),
    );
    frame.render_stateful_widget(interval_table, split[0], &mut state.life_timeline_table);
    let contributor_rows = interval.contributors.iter().map(|row| {
        let name = lifecycle
            .type_names
            .get(&row.gc_info)
            .cloned()
            .unwrap_or_else(|| format!("GCInfo {}", row.gc_info));
        Row::new(vec![
            name,
            if row.delta_bytes >= 0 {
                format!("+{}", format_bytes(row.delta_bytes as u64))
            } else {
                format!("-{}", format_bytes(row.delta_bytes.unsigned_abs()))
            },
            format_bytes(row.after_bytes),
        ])
    });
    let contributor_table = Table::new(
        contributor_rows,
        [
            Constraint::Min(24),
            Constraint::Length(12),
            Constraint::Length(12),
        ],
    )
    .header(
        Row::new(["Type contributor", "Net Δ", "After"]).style(
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
            .border_style(if state.life_timeline_focus_contributors {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default()
            })
            .title(format!("Contributors to {}", interval.label)),
    );
    frame.render_stateful_widget(
        contributor_table,
        split[1],
        &mut state.life_contributor_table,
    );
}

pub(super) fn draw_lifecycle(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    reports: &Reports,
    state: &mut State,
) {
    let [tabs_area, body] =
        Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).areas(area);
    frame.render_widget(
        Tabs::new(["1 Retention Profile", "2 GC Timeline", "3 Object Inspector"])
            .select(state.life_view)
            .highlight_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Capture-wide lifecycle workspace"),
            ),
        tabs_area,
    );
    match state.life_view {
        0 => draw_retention_profile(frame, body, reports, state),
        1 => draw_gc_timeline(frame, body, reports, state),
        _ => draw_object_inspector(frame, body, reports, state),
    }
}
