#![cfg(windows)]

mod cli;
mod etl;
mod reports;
mod symbols;
pub mod tui;

use etl::fast_decode;
use reports::{heaps, large_allocations, lifetimes, zones};
use symbols::attribution;

use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::time::Instant;
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError};
use windows_sys::Win32::System::Diagnostics::Etw::*;
use windows_sys::core::GUID;

const V8_GUID: &str = "57277741-3638-4a4b-bdba-0ac6e45da56c";
const MEMORY_GUID: &str = "3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c";
const THREAD_GUID: &str = "3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c";
const PERF_GUID: &str = "ce1dbfb4-137e-4da6-87b0-3f59aa102cbc";
const STACK_GUID: &str = "def2fe46-7bd6-4b80-bd94-f57fe20d0ce3";
const IMAGE_GUID: &str = "2cb15d1d-5fc1-11d2-abe1-00a0c911f518";
const MEMORY_PROBE_GUID: &str = "9eeb8a39-89e8-4c86-9f88-33083799f7d9";
const ZONE_GUID: &str = "76ec13f3-59c1-4527-a513-6453024cab81";
pub type Result<T> = std::result::Result<T, String>;

fn has_loss(events: u32, buffers: u32) -> bool {
    events != 0 || buffers != 0
}

fn guid(value: &GUID) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        value.data1,
        value.data2,
        value.data3,
        value.data4[0],
        value.data4[1],
        value.data4[2],
        value.data4[3],
        value.data4[4],
        value.data4[5],
        value.data4[6],
        value.data4[7]
    )
}

fn wide_string(bytes: &[u8], offset: u32) -> Result<String> {
    if offset == 0 {
        return Ok(String::new());
    }
    let start = usize::try_from(offset).map_err(|e| e.to_string())?;
    if start >= bytes.len() || start % 2 != 0 {
        return Err(format!("Invalid TDH string offset: {offset}"));
    }
    let mut words = Vec::new();
    for chunk in bytes[start..].as_chunks::<2>().0 {
        let word = u16::from_le_bytes([chunk[0], chunk[1]]);
        if word == 0 {
            return String::from_utf16(&words).map_err(|e| e.to_string());
        }
        words.push(word);
    }
    Err("Unterminated TDH string.".into())
}

#[derive(Clone)]
struct Property {
    name: String,
    input_type: u16,
    structured: bool,
    length_property: Option<String>,
}

#[derive(Clone)]
struct Schema {
    event_name: String,
    provider: String,
    task: String,
    opcode: String,
    properties: Vec<Property>,
}

// TDH returns variable-sized, aligned structures with offsets into the same buffer.
unsafe fn schema(record: *const EVENT_RECORD) -> Result<Schema> {
    let mut length = 0;
    let status = unsafe { TdhGetEventInformation(record, 0, null(), null_mut(), &mut length) };
    if status != ERROR_INSUFFICIENT_BUFFER {
        return Err(format!("TdhGetEventInformation(size): {status}"));
    }
    if length as usize > 16 * 1024 * 1024 || (length as usize) < size_of::<TRACE_EVENT_INFO>() {
        return Err(format!("Invalid TDH metadata length: {length}"));
    }
    let mut storage = vec![0u64; (length as usize).div_ceil(8)];
    let info = storage.as_mut_ptr().cast::<TRACE_EVENT_INFO>();
    let status = unsafe { TdhGetEventInformation(record, 0, null(), info, &mut length) };
    if status != 0 {
        return Err(format!("TdhGetEventInformation(data): {status}"));
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), length as usize) };
    let info = unsafe { &*info };
    let count = info.TopLevelPropertyCount as usize;
    let end = offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray)
        .checked_add(
            count
                .checked_mul(size_of::<EVENT_PROPERTY_INFO>())
                .ok_or("Property size overflow.")?,
        )
        .ok_or("Property metadata overflow.")?;
    if count > info.PropertyCount as usize || end > bytes.len() {
        return Err("TDH property array exceeds metadata buffer.".into());
    }
    let properties =
        unsafe { std::slice::from_raw_parts(info.EventPropertyInfoArray.as_ptr(), count) };
    let mut decoded = Vec::with_capacity(count);
    for property in properties {
        let structured = property.Flags & PropertyStruct != 0;
        decoded.push(Property {
            name: wide_string(bytes, property.NameOffset)?,
            input_type: if structured {
                0
            } else {
                unsafe { property.Anonymous1.nonStructType.InType }
            },
            structured,
            length_property: if property.Flags & PropertyParamLength != 0 {
                let index = unsafe { property.Anonymous3.lengthPropertyIndex } as usize;
                let length = properties
                    .get(index)
                    .ok_or("TDH length property exceeds schema.")?;
                Some(wide_string(bytes, length.NameOffset)?)
            } else {
                None
            },
        });
    }
    Ok(Schema {
        event_name: if info.DecodingSource == DecodingSourceTlg {
            wide_string(bytes, unsafe { info.Anonymous1.EventNameOffset })?
        } else {
            String::new()
        },
        provider: wide_string(bytes, info.ProviderNameOffset)?,
        task: wide_string(bytes, info.TaskNameOffset)?,
        opcode: wide_string(bytes, info.OpcodeNameOffset)?,
        properties: decoded,
    })
}

fn scalar_values(bytes: &[u8], width: usize, signed: bool, hex: bool) -> Result<Value> {
    if !matches!(width, 1 | 2 | 4 | 8) || bytes.is_empty() || !bytes.len().is_multiple_of(width) {
        return Err(format!(
            "Invalid scalar payload: {} bytes, width {width}",
            bytes.len()
        ));
    }
    let values: Vec<Value> = bytes
        .chunks_exact(width)
        .map(|chunk| {
            let mut buffer = [0u8; 8];
            buffer[..width].copy_from_slice(chunk);
            if signed && chunk[width - 1] & 0x80 != 0 {
                buffer[width..].fill(0xff);
            }
            let value = u64::from_le_bytes(buffer);
            if hex {
                json!(format!("0x{value:x}"))
            } else if signed {
                json!(value as i64)
            } else {
                json!(value)
            }
        })
        .collect();
    Ok(if values.len() == 1 {
        values[0].clone()
    } else {
        json!(values)
    })
}

fn property_value(bytes: &[u8], input_type: u16, pointer_size: usize) -> Result<Value> {
    match input_type {
        1 => {
            if !bytes.len().is_multiple_of(2) {
                return Err("Odd UTF-16 payload length.".into());
            }
            let words: Vec<u16> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|v| u16::from_le_bytes([v[0], v[1]]))
                .take_while(|v| *v != 0)
                .collect();
            Ok(json!(
                String::from_utf16(&words).map_err(|e| e.to_string())?
            ))
        }
        // ANSI encoding depends on the provider's code page; retain bytes without guessing UTF-8.
        2 | 14 => {
            Ok(json!({ "raw_hex": bytes.iter().map(|v| format!("{v:02x}")).collect::<String>() }))
        }
        3 | 4 => scalar_values(bytes, 1, input_type == 3, false),
        5 | 6 => scalar_values(bytes, 2, input_type == 5, false),
        7 | 8 | 13 | 20 => scalar_values(bytes, 4, input_type == 7, input_type == 20),
        9 | 10 | 17 | 21 => scalar_values(bytes, 8, input_type == 9, input_type == 21),
        16 => scalar_values(bytes, pointer_size, false, true),
        308 => scalar_values(bytes, pointer_size, false, false),
        _ => Ok(json!({
            "tdh_input_type": input_type,
            "raw_hex": bytes.iter().map(|v| format!("{v:02x}")).collect::<String>()
        })),
    }
}

unsafe fn properties(
    record: *const EVENT_RECORD,
    schema: &Schema,
) -> Result<BTreeMap<String, Value>> {
    let record_ref = unsafe { &*record };
    let pointer_size = if record_ref.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER as u16 != 0
    {
        4
    } else {
        8
    };
    let mut values = BTreeMap::new();
    for property in &schema.properties {
        if property.structured {
            return Err(format!(
                "Structured TDH property requires an explicit decoder: {}",
                property.name
            ));
        }
        let name: Vec<u16> = property.name.encode_utf16().chain(Some(0)).collect();
        let descriptor = PROPERTY_DATA_DESCRIPTOR {
            PropertyName: name.as_ptr() as u64,
            ArrayIndex: u32::MAX,
            Reserved: 0,
        };
        let mut length = 0;
        let status = unsafe { TdhGetPropertySize(record, 0, null(), 1, &descriptor, &mut length) };
        if status != 0 {
            return Err(format!("TdhGetPropertySize({}): {status}", property.name));
        }
        if length > 16 * 1024 * 1024 {
            return Err("TDH property exceeds size limit.".into());
        }
        let mut bytes = vec![0u8; length as usize];
        if length != 0 {
            let status = unsafe {
                TdhGetProperty(
                    record,
                    0,
                    null(),
                    1,
                    &descriptor,
                    length,
                    bytes.as_mut_ptr(),
                )
            };
            if status != 0 {
                return Err(format!("TdhGetProperty({}): {status}", property.name));
            }
        }
        let mut value = if guid(&record_ref.EventHeader.ProviderId) == MEMORY_PROBE_GUID
            && property.input_type == 2
        {
            json!(
                std::str::from_utf8(bytes.split(|v| *v == 0).next().unwrap_or(&[]))
                    .map_err(|e| e.to_string())?
            )
        } else {
            property_value(&bytes, property.input_type, pointer_size)?
        };
        if guid(&record_ref.EventHeader.ProviderId) == MEMORY_PROBE_GUID
            && property.name == "NativeStack"
        {
            value = heaps::stack_frames(
                value["raw_hex"]
                    .as_str()
                    .ok_or("Native stack is not binary.")?,
            )?;
        }
        values.insert(property.name.clone(), value);
    }
    Ok(values)
}

fn field_u32(fields: &BTreeMap<String, Value>, names: &[&str]) -> Option<u32> {
    fields.iter().find_map(|(key, value)| {
        if names.iter().any(|name| key.eq_ignore_ascii_case(name)) {
            value.as_u64().and_then(|v| u32::try_from(v).ok())
        } else {
            None
        }
    })
}

// Classic StackWalk opcode 32 has a fixed prefix and a variable-length frame tail.
fn stack_properties(bytes: &[u8], pointer_size: usize) -> Result<BTreeMap<String, Value>> {
    if !matches!(pointer_size, 4 | 8)
        || bytes.len() < 16
        || !(bytes.len() - 16).is_multiple_of(pointer_size)
    {
        return Err("Invalid classic StackWalk payload length.".into());
    }
    Ok(BTreeMap::from([
        (
            "EventTimeStamp".into(),
            scalar_values(&bytes[..8], 8, false, false)?,
        ),
        (
            "StackProcess".into(),
            scalar_values(&bytes[8..12], 4, false, false)?,
        ),
        (
            "StackThread".into(),
            scalar_values(&bytes[12..16], 4, false, false)?,
        ),
        (
            "Frames".into(),
            if bytes.len() == 16 {
                json!([])
            } else {
                let values: Vec<Value> = bytes[16..]
                    .chunks_exact(pointer_size)
                    .map(|frame| scalar_values(frame, pointer_size, false, true))
                    .collect::<Result<_>>()?;
                json!(values)
            },
        ),
    ]))
}

#[derive(Serialize, Default)]
struct Summary {
    schema_version: u32,
    trace: PathBuf,
    target_pid: u32,
    events_lost: u32,
    buffers_lost: u32,
    complete: bool,
    timestamp_clock_type: u32,
    performance_frequency: i64,
    total_events: u64,
    selected_events: u64,
    target_events: u64,
    selected_by_kind: BTreeMap<String, u64>,
    metadata_errors: BTreeMap<String, u64>,
    property_errors: BTreeMap<String, u64>,
    selected_by_event: BTreeMap<String, u64>,
    limitations: Vec<String>,
    decode_elapsed_ms: u128,
    schema_queries: u64,
    probe_fast_decodes: u64,
}

struct Consumer {
    summary: Summary,
    output: BufWriter<File>,
    schemas: BTreeMap<Vec<u8>, Option<Arc<Schema>>>,
    threads: BTreeMap<u32, u32>,
    fatal: Option<String>,
    started: Instant,
    last_progress: Instant,
    tdh_probe: bool,
}

impl Consumer {
    unsafe fn event(&mut self, record: &EVENT_RECORD) -> Result<()> {
        self.summary.total_events += 1;
        let header = &record.EventHeader;
        if self.last_progress.elapsed().as_secs() >= 10 {
            eprintln!(
                "ETL decode: {} events, {} selected, {} schemas, {:.1}s",
                self.summary.total_events,
                self.summary.selected_events,
                self.summary.schema_queries,
                self.started.elapsed().as_secs_f64()
            );
            self.last_progress = Instant::now();
        }
        if !matches!(
            header.ProviderId.data1,
            0x57277741
                | 0x3d6fa8d3
                | 0xce1dbfb4
                | 0xdef2fe46
                | 0x3d6fa8d1
                | 0x2cb15d1d
                | 0x9eeb8a39
                | 0x76ec13f3
        ) {
            return Ok(());
        }
        let provider = guid(&header.ProviderId);
        let descriptor = &header.EventDescriptor;
        if provider == ZONE_GUID {
            if header.ProcessId != self.summary.target_pid {
                return Ok(());
            }
            if record.UserData.is_null() || descriptor.Id != 1 {
                return Err("Invalid Zone event payload/ID.".into());
            }
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    record.UserData.cast::<u8>(),
                    record.UserDataLength as usize,
                )
            };
            let fields = zones::decode(bytes)?;
            self.summary.selected_events += 1;
            self.summary.target_events += 1;
            *self
                .summary
                .selected_by_kind
                .entry("zone_probe".into())
                .or_default() += 1;
            *self
                .summary
                .selected_by_event
                .entry(format!("{provider}/1:ZoneMemory"))
                .or_default() += 1;
            serde_json::to_writer(
                &mut self.output,
                &json!({
                    "kind":"zone_probe","event_name":"ZoneMemory",
                    "timestamp_raw":header.TimeStamp.to_string(),
                    "pid":header.ProcessId,"header_pid":header.ProcessId,"tid":header.ThreadId,
                    "provider_guid":provider,"provider":"V8.ZoneMemory",
                    "event_id":1,"opcode":descriptor.Opcode,
                    "task_name":"","opcode_name":"","properties":fields
                }),
            )
            .map_err(|e| e.to_string())?;
            return self.output.write_all(b"\n").map_err(|e| e.to_string());
        }
        let is_v8 = provider == V8_GUID;
        let is_memory = provider == MEMORY_GUID && matches!(descriptor.Opcode, 98 | 99);
        let is_sample = provider == PERF_GUID && descriptor.Opcode == 46;
        let is_stack = provider == STACK_GUID && descriptor.Opcode == 32;
        let is_thread = provider == THREAD_GUID && matches!(descriptor.Opcode, 1..=4);
        let is_image = provider == IMAGE_GUID && matches!(descriptor.Opcode, 2..=4 | 10);
        let is_probe = provider == MEMORY_PROBE_GUID;
        if !is_v8 && !is_memory && !is_sample && !is_stack && !is_thread && !is_image && !is_probe {
            return Ok(());
        }
        if (is_v8 || is_probe) && header.ProcessId != self.summary.target_pid {
            return Ok(());
        }
        if is_stack {
            if record.UserDataLength < 16 || record.UserData.is_null() {
                return Err("Truncated classic StackWalk prefix.".into());
            }
            let prefix = unsafe { std::slice::from_raw_parts(record.UserData.cast::<u8>(), 16) };
            let pid = u32::from_le_bytes(
                prefix[8..12]
                    .try_into()
                    .map_err(|_| "Invalid StackWalk PID.")?,
            );
            if pid != self.summary.target_pid {
                return Ok(());
            }
        }
        let key = format!(
            "{provider}:{}:{}:{}:{}:{}:{}",
            descriptor.Id,
            descriptor.Version,
            descriptor.Opcode,
            descriptor.Task,
            descriptor.Keyword,
            header.Flags
        );
        // TraceLogging events may reuse descriptors with different embedded schemas.
        let embedded_schema = if record.ExtendedDataCount == 0 {
            None
        } else {
            if record.ExtendedData.is_null() {
                return Err("Null extended-data array.".into());
            }
            unsafe {
                std::slice::from_raw_parts(record.ExtendedData, record.ExtendedDataCount as usize)
            }
            .iter()
            .find(|item| item.ExtType == EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL as u16)
        };
        let mut cache_key = key.as_bytes().to_vec();
        cache_key.push(0);
        if let Some(item) = embedded_schema {
            if item.DataPtr == 0 || item.DataSize == 0 {
                return Err("Missing TraceLogging schema payload.".into());
            }
            // Include the exact embedded metadata, not just the descriptor:
            // TraceLogging providers may reuse ID 0 for unrelated events.
            let metadata = unsafe {
                std::slice::from_raw_parts(item.DataPtr as *const u8, item.DataSize as usize)
            };
            cache_key.extend_from_slice(metadata);
        }
        if !self.schemas.contains_key(&cache_key) {
            if self.schemas.len() >= 4096 {
                return Err("ETL exceeds 4096 distinct schema limit.".into());
            }
            self.summary.schema_queries += 1;
            let decoded = match unsafe { schema(record) } {
                Ok(schema) => Some(Arc::new(schema)),
                Err(error) => {
                    *self.summary.metadata_errors.entry(error).or_default() += 1;
                    None
                }
            };
            self.schemas.insert(cache_key.clone(), decoded);
        }
        let decoded = self.schemas.get(&cache_key).cloned().flatten();
        let Some(schema) = decoded else {
            return Ok(());
        };
        let decoded_fields = if is_probe && !self.tdh_probe {
            let bytes = if record.UserDataLength == 0 {
                &[][..]
            } else {
                if record.UserData.is_null() {
                    return Err("Null memory-probe payload.".into());
                }
                unsafe {
                    std::slice::from_raw_parts(
                        record.UserData.cast::<u8>(),
                        record.UserDataLength as usize,
                    )
                }
            };
            let pointer_size = if header.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER as u16 != 0 {
                4
            } else {
                8
            };
            self.summary.probe_fast_decodes += 1;
            fast_decode::probe_properties(bytes, &schema, pointer_size)
        } else if is_stack {
            if record.UserData.is_null() && record.UserDataLength != 0 {
                return Err("Null StackWalk payload.".into());
            }
            let bytes = if record.UserDataLength == 0 {
                &[][..]
            } else {
                unsafe {
                    std::slice::from_raw_parts(
                        record.UserData.cast::<u8>(),
                        record.UserDataLength as usize,
                    )
                }
            };
            let pointer_size = if header.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER as u16 != 0 {
                4
            } else {
                8
            };
            stack_properties(bytes, pointer_size)
        } else {
            unsafe { properties(record, &schema) }
        };
        let fields = match decoded_fields {
            Ok(fields) => fields,
            Err(error) => {
                *self
                    .summary
                    .property_errors
                    .entry(format!("{key}: {error}"))
                    .or_default() += 1;
                return Ok(());
            }
        };
        if is_thread
            && let (Some(tid), Some(pid)) = (
                field_u32(&fields, &["TThreadId", "ThreadId"]),
                field_u32(&fields, &["ProcessId", "PID"]),
            )
        {
            self.threads.insert(tid, pid);
        }
        let payload_pid = field_u32(&fields, &["ProcessId", "StackProcess", "PID"]);
        let payload_tid = field_u32(&fields, &["ThreadId", "TThreadId", "StackThread"]);
        let mapped_pid = payload_tid.and_then(|tid| self.threads.get(&tid).copied());
        let pid = payload_pid.or(mapped_pid).unwrap_or(header.ProcessId);
        if pid != self.summary.target_pid && !(is_image && pid == 0) {
            return Ok(());
        }
        if pid == self.summary.target_pid {
            self.summary.target_events += 1;
        }
        let kind = if is_v8 {
            "v8_jit"
        } else if is_memory {
            "virtual_memory"
        } else if is_sample {
            "cpu_sample"
        } else if is_stack {
            "stack"
        } else if is_image {
            "image"
        } else if is_probe {
            "heap_probe"
        } else {
            "thread"
        };
        self.summary.selected_events += 1;
        *self
            .summary
            .selected_by_kind
            .entry(kind.into())
            .or_default() += 1;
        *self
            .summary
            .selected_by_event
            .entry(format!(
                "{provider}/{}:{}/{}:{}",
                descriptor.Id, descriptor.Opcode, schema.task, schema.opcode
            ))
            .or_default() += 1;
        serde_json::to_writer(
            &mut self.output,
            &json!({
                "kind": kind,
                "event_name": schema.event_name,
                "timestamp_raw": header.TimeStamp.to_string(),
                "pid": pid,
                "header_pid": header.ProcessId,
                "tid": payload_tid.unwrap_or(header.ThreadId),
                "provider_guid": provider,
                "provider": schema.provider,
                "event_id": descriptor.Id,
                "opcode": descriptor.Opcode,
                "task_name": schema.task,
                "opcode_name": schema.opcode,
                "properties": fields,
            }),
        )
        .map_err(|e| e.to_string())?;
        self.output.write_all(b"\n").map_err(|e| e.to_string())
    }
}

unsafe extern "system" fn event_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let record = unsafe { &*record };
    if record.UserContext.is_null() {
        return;
    }
    let consumer = unsafe { &mut *record.UserContext.cast::<Consumer>() };
    if consumer.fatal.is_some() {
        return;
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        consumer.event(record)
    }));
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => consumer.fatal = Some(error),
        Err(_) => consumer.fatal = Some("Native ETW callback panicked; analysis aborted.".into()),
    }
}

fn analyze(options: cli::DecodeOptions) -> Result<()> {
    if !options.trace.is_file() {
        return Err("ETL input does not exist.".into());
    }
    if options.output.exists() {
        return Err("Output directory already exists; refusing to overwrite.".into());
    }
    fs::create_dir_all(&options.output).map_err(|e| e.to_string())?;
    let mut filename: Vec<u16> = options
        .trace
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut consumer = Consumer {
        summary: Summary {
            schema_version: 2,
            trace: fs::canonicalize(&options.trace).map_err(|e| e.to_string())?,
            target_pid: options.pid,
            limitations: vec![
                "VirtualAlloc activity describes reservations/commit/decommit, not cppgc object sizes or RSS.".into(),
                "Symbol attribution is optional and reports PDB/JIT/unresolved coverage separately.".into(),
                "StackWalk EventTimeStamp correlates to source timestamp_raw; timestamps use the ETL's raw clock.".into(),
                "Events before the recording and events from child processes are not included.".into(),
                "Missing schemas/property errors are reported explicitly; inspect before quantitative conclusions.".into(),
            ],
            ..Summary::default()
        },
        output: BufWriter::with_capacity(1024 * 1024, File::create(options.output.join("events.jsonl")).map_err(|e| e.to_string())?),
        schemas: BTreeMap::new(),
        threads: BTreeMap::new(),
        fatal: None,
        started: Instant::now(),
        last_progress: Instant::now(),
        tdh_probe: options.tdh_probe,
    };
    let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
    logfile.LogFileName = filename.as_mut_ptr();
    logfile.Anonymous1.ProcessTraceMode =
        PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    logfile.Anonymous2.EventRecordCallback = Some(event_callback);
    logfile.Context = (&mut consumer as *mut Consumer).cast();
    let handle = unsafe { OpenTraceW(&mut logfile) };
    if handle.Value == u64::MAX {
        return Err(format!("OpenTraceW failed: {}", unsafe { GetLastError() }));
    }
    consumer.summary.events_lost = unsafe { logfile.LogfileHeader.Anonymous2.Anonymous.EventsLost };
    consumer.summary.buffers_lost = logfile.LogfileHeader.BuffersLost;
    consumer.summary.timestamp_clock_type = logfile.LogfileHeader.ReservedFlags;
    consumer.summary.performance_frequency = logfile.LogfileHeader.PerfFreq;
    let status = unsafe { ProcessTrace(&handle, 1, null(), null()) };
    let close_status = unsafe { CloseTrace(handle) };
    consumer.output.flush().map_err(|e| e.to_string())?;
    consumer.summary.decode_elapsed_ms = consumer.started.elapsed().as_millis();
    consumer.summary.events_lost = consumer.summary.events_lost.max(logfile.EventsLost);
    consumer.summary.complete = status == 0
        && consumer.fatal.is_none()
        && !has_loss(consumer.summary.events_lost, consumer.summary.buffers_lost)
        && consumer.summary.target_events > 0
        && consumer.summary.metadata_errors.is_empty()
        && consumer.summary.property_errors.is_empty();
    let report = serde_json::to_string_pretty(&consumer.summary).map_err(|e| e.to_string())?;
    fs::write(options.output.join("summary.json"), &report).map_err(|e| e.to_string())?;
    println!("{report}");
    if status != 0 {
        return Err(format!("ProcessTrace failed: {status}"));
    }
    if close_status != 0 {
        return Err(format!("CloseTrace failed: {close_status}"));
    }
    if let Some(error) = consumer.fatal {
        return Err(error);
    }
    if !options.allow_loss && has_loss(consumer.summary.events_lost, consumer.summary.buffers_lost)
    {
        return Err("ETL contains lost events/buffers. Recapture, or explicitly use --allow-loss for incomplete diagnosis.".into());
    }
    if !consumer.summary.metadata_errors.is_empty() || !consumer.summary.property_errors.is_empty()
    {
        return Err("Incomplete decoding; inspect schema/property errors in summary.json.".into());
    }
    if consumer.summary.target_events == 0 {
        return Err("No decodable events matched the requested PID.".into());
    }
    build_reports(
        &options.output,
        &options.symbol_dirs,
        &options.required_pdbs,
        consumer.summary.selected_by_kind.contains_key("heap_probe"),
    )
}

fn build_reports(
    directory: &std::path::Path,
    symbols: &[PathBuf],
    required: &[String],
    heap_probe: bool,
) -> Result<()> {
    let mut timings = serde_json::Map::new();
    let summary: Value = serde_json::from_slice(
        &fs::read(directory.join("summary.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if !directory.join("zone-report.json").exists()
        && summary["selected_by_kind"]["zone_probe"]
            .as_u64()
            .is_some_and(|count| count > 0)
    {
        eprintln!("Reconstructing compiler Zone segments...");
        let clock = Instant::now();
        zones::run(directory)?;
        timings.insert("zone_report_ms".into(), json!(clock.elapsed().as_millis()));
    }
    if heap_probe {
        eprintln!("ETL decoded; building heap checkpoint report...");
        let clock = Instant::now();
        heaps::run(directory)?;
        timings.insert("heap_report_ms".into(), json!(clock.elapsed().as_millis()));
        eprintln!("Building exact cppgc lifetime history...");
        let clock = Instant::now();
        lifetimes::run(directory)?;
        timings.insert(
            "lifetime_report_ms".into(),
            json!(clock.elapsed().as_millis()),
        );
    }
    if !symbols.is_empty() {
        eprintln!("Resolving local symbols and allocation paths...");
        let clock = Instant::now();
        attribution::run(directory, symbols, required)?;
        timings.insert(
            "symbol_attribution_ms".into(),
            json!(clock.elapsed().as_millis()),
        );
    } else if !required.is_empty() {
        return Err("--require-pdb needs at least one --symbols-dir.".into());
    }
    fs::write(
        directory.join("analysis-timings.json"),
        serde_json::to_vec_pretty(&timings).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn validated_decode_summary(directory: &Path) -> Result<Value> {
    let path = directory.join("summary.json");
    if fs::metadata(&path).map_err(|e| e.to_string())?.len() > 1024 * 1024 {
        return Err("Decode summary exceeds size limit.".into());
    }
    let summary: Value = serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    if summary["complete"] != true
        || summary["events_lost"].as_u64() != Some(0)
        || summary["buffers_lost"].as_u64() != Some(0)
        || summary["target_events"]
            .as_u64()
            .is_none_or(|count| count == 0)
    {
        return Err("Report resume requires a complete loss-free target decode.".into());
    }
    Ok(summary)
}

pub fn run() {
    cli::run();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_resume_requires_complete_loss_free_target_summary() {
        let directory =
            std::env::temp_dir().join(format!("v8-decode-summary-test-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("summary.json");
        assert!(validated_decode_summary(&directory).is_err());
        let valid = json!({
            "complete":true, "events_lost":0, "buffers_lost":0, "target_events":1
        });
        fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
        assert!(validated_decode_summary(&directory).is_ok());
        for (key, value) in [
            ("complete", json!(false)),
            ("events_lost", json!(1)),
            ("buffers_lost", json!(1)),
            ("target_events", json!(0)),
            ("events_lost", Value::Null),
        ] {
            let mut invalid = valid.clone();
            invalid[key] = value;
            fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
            assert!(validated_decode_summary(&directory).is_err());
        }
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn either_lost_events_or_buffers_invalidates_transport() {
        assert!(!has_loss(0, 0));
        assert!(has_loss(1, 0));
        assert!(has_loss(0, 1));
    }

    #[test]
    fn signed_values_are_sign_extended() {
        assert_eq!(scalar_values(&[0xff], 1, true, false).unwrap(), json!(-1));
        assert_eq!(
            scalar_values(&[0, 0x80], 2, true, false).unwrap(),
            json!(-32768)
        );
    }

    #[test]
    fn arrays_and_pointer_addresses_are_preserved() {
        assert_eq!(
            scalar_values(&[1, 0, 2, 0], 2, false, false).unwrap(),
            json!([1, 2])
        );
        assert_eq!(
            property_value(&[0xff; 8], 16, 8).unwrap(),
            json!("0xffffffffffffffff")
        );
        assert_eq!(property_value(&[0xff; 8], 308, 8).unwrap(), json!(u64::MAX));
    }

    #[test]
    fn malformed_scalar_and_strings_are_rejected() {
        assert!(scalar_values(&[1, 2, 3], 4, false, false).is_err());
        assert!(scalar_values(&[1], 0, false, false).is_err());
        assert!(property_value(&[1], 1, 8).is_err());
        assert!(wide_string(&[0, 0, 65, 0], 2).is_err());
        assert!(wide_string(&[0, 0], 3).is_err());
    }

    #[test]
    fn strings_and_unknown_types_preserve_data() {
        assert_eq!(property_value(&[65, 0, 0, 0], 1, 8).unwrap(), json!("A"));
        assert_eq!(
            property_value(&[0xff], 2, 8).unwrap(),
            json!({"raw_hex": "ff"})
        );
        assert_eq!(
            property_value(&[1], 999, 8).unwrap(),
            json!({"tdh_input_type": 999, "raw_hex": "01"})
        );
    }

    #[test]
    fn process_ids_are_bounded_and_case_insensitive() {
        let fields = BTreeMap::from([("ProcessID".into(), json!(42))]);
        assert_eq!(field_u32(&fields, &["ProcessId"]), Some(42));
        let fields = BTreeMap::from([("ProcessId".into(), json!(u64::MAX))]);
        assert_eq!(field_u32(&fields, &["ProcessId"]), None);
    }

    #[test]
    fn variable_stack_depth_is_decoded_without_fixed_mof_fields() {
        let mut bytes = vec![0u8; 16];
        bytes[8..12].copy_from_slice(&42u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&7u32.to_le_bytes());
        bytes.extend_from_slice(&0x1234u64.to_le_bytes());
        let fields = stack_properties(&bytes, 8).unwrap();
        assert_eq!(field_u32(&fields, &["StackProcess"]), Some(42));
        assert_eq!(fields["Frames"], json!(["0x1234"]));
        assert!(stack_properties(&bytes[..23], 8).is_err());
        assert!(stack_properties(&bytes, 0).is_err());
        assert_eq!(
            stack_properties(&bytes[..16], 8).unwrap()["Frames"],
            json!([])
        );
    }
}
