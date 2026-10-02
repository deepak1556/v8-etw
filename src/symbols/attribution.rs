use crate::{Result, guid};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;
use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::core::GUID;

static DBGHELP: Mutex<()> = Mutex::new(());

#[derive(Deserialize)]
struct Event {
    #[serde(default)]
    event_name: String,
    kind: String,
    timestamp_raw: String,
    tid: u32,
    opcode: u8,
    event_id: u16,
    properties: BTreeMap<String, Value>,
}

fn number(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        value.as_str().and_then(|v| {
            if let Some(hex) = v.strip_prefix("0x") {
                u64::from_str_radix(hex, 16).ok()
            } else {
                v.parse().ok()
            }
        })
    })
}

fn numeric(fields: &BTreeMap<String, Value>, name: &str) -> Result<u64> {
    fields
        .get(name)
        .and_then(number)
        .ok_or_else(|| format!("Missing numeric field {name}"))
}

#[derive(Default)]
struct Origin {
    kinds: BTreeSet<String>,
    cpu_samples: u64,
    alloc_events: u64,
    free_events: u64,
    requested_commit_bytes: u64,
    requested_reserve_bytes: u64,
}

#[derive(Default, Serialize)]
struct Inclusive {
    cpu_samples: u64,
    virtual_alloc_events: u64,
    virtual_free_events: u64,
    requested_commit_bytes: u64,
    requested_reserve_bytes: u64,
}

#[derive(Default, Serialize)]
struct AllocationTraffic {
    samples: u64,
    sampled_requested_bytes: u64,
    estimated_native_bytes: u64,
    estimated_cppgc_traffic_bytes: u64,
    exact_cppgc_allocations: u64,
    exact_cppgc_allocated_bytes: u64,
    zone_segment_count: u64,
    zone_segment_capacity_bytes: u64,
}

fn text(fields: &BTreeMap<String, Value>, name: &str) -> Result<String> {
    fields
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("Missing string field {name}"))
}

fn events(path: &Path, mut visitor: impl FnMut(Event) -> Result<()>) -> Result<()> {
    for (index, line) in
        BufReader::with_capacity(1024 * 1024, File::open(path).map_err(|e| e.to_string())?)
            .lines()
            .enumerate()
    {
        let line = line.map_err(|e| e.to_string())?;
        if line.contains("\"kind\":\"heap_probe\"")
            && (!line.contains("\"event_name\":\"NativeSampleAdded\"")
                && !line.contains("\"event_name\":\"CppgcAllocationTraffic\"")
                && !(line.contains("\"event_name\":\"CppgcLifetime\"")
                    && !line.contains("\"NativeStack\":[]")))
        {
            continue;
        }
        let event =
            serde_json::from_str(&line).map_err(|e| format!("JSONL line {}: {e}", index + 1))?;
        visitor(event)?;
    }
    Ok(())
}

#[derive(Clone, Serialize)]
struct Module {
    name: String,
    recorded_path: String,
    base: u64,
    size: u64,
    loaded_at: u64,
    unloaded_at: Option<u64>,
    timestamp: u32,
    checksum: u32,
}

#[derive(Clone)]
struct Method {
    base: u64,
    size: u64,
    loaded_at: u64,
    name: String,
    source_key: (u64, u64),
    line: u64,
    column: u64,
}

struct RangeIndex {
    ordered: Vec<(u64, usize)>,
    prefix_end: Vec<u128>,
}

impl RangeIndex {
    fn new(ranges: impl Iterator<Item = (u64, u64)>) -> Self {
        let ranges: Vec<_> = ranges.collect();
        let mut ordered: Vec<_> = ranges
            .iter()
            .enumerate()
            .map(|(index, (base, _))| (*base, index))
            .collect();
        ordered.sort_by_key(|(base, _)| *base);
        let mut maximum = 0;
        let prefix_end = ordered
            .iter()
            .map(|(base, index)| {
                maximum = maximum.max(u128::from(*base) + u128::from(ranges[*index].1));
                maximum
            })
            .collect();
        Self {
            ordered,
            prefix_end,
        }
    }

    fn candidates(&self, address: u64) -> impl Iterator<Item = usize> + '_ {
        let end = self.ordered.partition_point(|(base, _)| *base <= address);
        (0..end)
            .rev()
            .take_while(move |position| self.prefix_end[*position] > u128::from(address))
            .map(|position| self.ordered[position].1)
    }
}

fn method_at(
    index: &RangeIndex,
    methods: &[Method],
    address: u64,
    timestamp: u64,
) -> Option<usize> {
    index
        .candidates(address)
        .filter(|position| {
            let method = &methods[*position];
            timestamp >= method.loaded_at && in_range(method.base, method.size, address)
        })
        .max_by_key(|position| (methods[*position].loaded_at, *position))
}

fn in_range(base: u64, size: u64, address: u64) -> bool {
    address
        .checked_sub(base)
        .is_some_and(|offset| offset < size)
}

fn lookup_address(address: u64, is_return_address: bool) -> u64 {
    if is_return_address {
        address.saturating_sub(1)
    } else {
        address
    }
}

pub(crate) fn function_key(frame: &Value) -> String {
    let function = frame
        .get("function")
        .and_then(Value::as_str)
        .unwrap_or("<unresolved>");
    let module = frame.get("module").and_then(Value::as_str);
    if let Some(module) = module {
        return format!("{module}!{function}");
    }
    if frame.get("status").and_then(Value::as_str) != Some("jit") {
        return format!("<unknown>!{function}");
    }
    let source = frame
        .get("source_file")
        .and_then(Value::as_str)
        .unwrap_or("<unknown>");
    let line = frame
        .get("source_line")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let column = frame
        .get("source_column")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    format!("<jit>!{function}@{source}:{line}:{column}")
}

#[cfg(test)]
fn module_at(modules: &[Module], address: u64, timestamp: u64) -> Option<usize> {
    modules
        .iter()
        .enumerate()
        .filter(|(_, module)| {
            in_range(module.base, module.size, address)
                && timestamp >= module.loaded_at
                && module.unloaded_at.is_none_or(|end| timestamp < end)
        })
        .max_by_key(|(_, module)| module.loaded_at)
        .map(|(index, _)| index)
}

fn indexed_module_at(
    index: &RangeIndex,
    modules: &[Module],
    address: u64,
    timestamp: u64,
) -> Option<usize> {
    index
        .candidates(address)
        .filter(|position| {
            let module = &modules[*position];
            in_range(module.base, module.size, address)
                && timestamp >= module.loaded_at
                && module.unloaded_at.is_none_or(|end| timestamp < end)
        })
        .max_by_key(|position| (modules[*position].loaded_at, *position))
}

fn read_at(file: &mut File, offset: u64, length: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0; length];
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| e.to_string())?;
    file.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or("Truncated PE field.")?
            .try_into()
            .map_err(|_| "Invalid PE field.")?,
    ))
}

struct PeIdentity {
    timestamp: u32,
    checksum: u32,
    image_size: u32,
    pdb_guid: Option<String>,
    pdb_age: Option<u32>,
}

fn pe_identity(path: &Path) -> Result<PeIdentity> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let dos = read_at(&mut file, 0, 64)?;
    if &dos[..2] != b"MZ" {
        return Err("Not a PE image.".into());
    }
    let nt = u32_at(&dos, 60)? as u64;
    let header = read_at(&mut file, nt, 24)?;
    if &header[..4] != b"PE\0\0" {
        return Err("Invalid PE signature.".into());
    }
    let sections = u16::from_le_bytes([header[6], header[7]]) as usize;
    let optional_size = u16::from_le_bytes([header[20], header[21]]) as usize;
    if sections > 96 || optional_size < 112 {
        return Err("Invalid PE header sizes.".into());
    }
    let optional = read_at(&mut file, nt + 24, optional_size)?;
    let data_directory = match u16::from_le_bytes([optional[0], optional[1]]) {
        0x20b => 112,
        0x10b => 96,
        _ => return Err("Unsupported PE optional header.".into()),
    };
    let mut identity = PeIdentity {
        timestamp: u32_at(&header, 8)?,
        checksum: u32_at(&optional, 64)?,
        image_size: u32_at(&optional, 56)?,
        pdb_guid: None,
        pdb_age: None,
    };
    let debug_rva = u32_at(&optional, data_directory + 6 * 8)?;
    let debug_size = u32_at(&optional, data_directory + 6 * 8 + 4)? as usize;
    if debug_rva == 0 {
        return Ok(identity);
    }
    if debug_size > 65536 || !debug_size.is_multiple_of(28) {
        return Err("Invalid PE debug directory.".into());
    }
    let table = read_at(&mut file, nt + 24 + optional_size as u64, sections * 40)?;
    let mut debug_offset = None;
    for section in table.as_chunks::<40>().0 {
        let virtual_address = u32_at(section, 12)?;
        let raw_size = u32_at(section, 16)?;
        if let Some(delta) = debug_rva.checked_sub(virtual_address)
            && (delta as usize)
                .checked_add(debug_size)
                .is_some_and(|end| end <= raw_size as usize)
        {
            debug_offset = Some(u32_at(section, 20)? as u64 + delta as u64);
            break;
        }
    }
    let debug = read_at(
        &mut file,
        debug_offset.ok_or("PE debug RVA has no file mapping.")?,
        debug_size,
    )?;
    for entry in debug.as_chunks::<28>().0 {
        if u32_at(entry, 12)? != 2 {
            continue;
        }
        let length = u32_at(entry, 16)? as usize;
        if !(24..=65536).contains(&length) {
            return Err("Invalid CodeView record size.".into());
        }
        let cv = read_at(&mut file, u32_at(entry, 24)? as u64, length)?;
        if &cv[..4] != b"RSDS" {
            continue;
        }
        let signature = GUID {
            data1: u32_at(&cv, 4)?,
            data2: u16::from_le_bytes([cv[8], cv[9]]),
            data3: u16::from_le_bytes([cv[10], cv[11]]),
            data4: cv[12..20]
                .try_into()
                .map_err(|_| "Invalid CodeView GUID.")?,
        };
        identity.pdb_guid = Some(guid(&signature));
        identity.pdb_age = Some(u32_at(&cv, 20)?);
    }
    Ok(identity)
}

fn validate_image(module: &Module, pe: &PeIdentity) -> Result<()> {
    if module.timestamp != pe.timestamp
        || module.size != pe.image_size as u64
        || (module.checksum != 0 && module.checksum != pe.checksum)
    {
        return Err("Local PE timestamp/size/checksum does not match recorded image.".into());
    }
    Ok(())
}

fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn utf16(value: &[u16]) -> String {
    String::from_utf16_lossy(&value[..value.iter().position(|v| *v == 0).unwrap_or(value.len())])
}

#[derive(Clone, Serialize)]
struct ModuleSymbols {
    module: Module,
    image_path: Option<PathBuf>,
    pdb_path: Option<String>,
    pdb_guid: Option<String>,
    pdb_age: Option<u32>,
    status: String,
    diagnostic: Option<String>,
    #[serde(skip)]
    symbol_base: u64,
}

struct Symbols {
    handle: HANDLE,
    _guard: MutexGuard<'static, ()>,
}

impl Symbols {
    fn new(directories: &[PathBuf]) -> Result<Self> {
        let guard = DBGHELP.lock().map_err(|e| e.to_string())?;
        let mut paths = Vec::new();
        for directory in directories {
            let path = fs::canonicalize(directory).map_err(|e| format!("Symbol directory: {e}"))?;
            let name = path.to_string_lossy().into_owned();
            if name.contains(';') || name.contains('*') || name.starts_with(r"\\?\UNC\") {
                return Err(
                    "Symbol paths must be local directories, not symbol-server/UNC paths.".into(),
                );
            }
            paths.push(name);
        }
        let path = wide(std::ffi::OsStr::new(&paths.join(";")));
        let handle = 1usize as HANDLE;
        unsafe {
            SymSetOptions(
                SYMOPT_EXACT_SYMBOLS
                    | SYMOPT_LOAD_LINES
                    | SYMOPT_UNDNAME
                    | SYMOPT_FAIL_CRITICAL_ERRORS
                    | SYMOPT_NO_PROMPTS
                    | SYMOPT_IGNORE_NT_SYMPATH
                    | SYMOPT_DISABLE_SYMSRV_AUTODETECT,
            );
            if SymInitializeW(handle, path.as_ptr(), 0) == 0 {
                return Err(format!("SymInitializeW: {}", GetLastError()));
            }
        }
        Ok(Self {
            handle,
            _guard: guard,
        })
    }

    fn load(&self, module: &Module, directories: &[PathBuf], index: usize) -> ModuleSymbols {
        let mut report = ModuleSymbols {
            module: module.clone(),
            image_path: None,
            pdb_path: None,
            pdb_guid: None,
            pdb_age: None,
            status: "unresolved".into(),
            diagnostic: None,
            symbol_base: 0,
        };
        let result = (|| -> Result<()> {
            let mut candidates: Vec<PathBuf> = directories
                .iter()
                .map(|dir| dir.join(&module.name))
                .collect();
            let recorded = PathBuf::from(&module.recorded_path);
            if module.recorded_path.as_bytes().get(1) == Some(&b':') {
                candidates.push(recorded);
            }
            if let Some(system) = std::env::var_os("SystemRoot") {
                candidates.push(PathBuf::from(system).join("System32").join(&module.name));
            }
            let mut mismatches = Vec::new();
            let mut matching = None;
            for path in candidates {
                if !path.is_file() {
                    continue;
                }
                let pe = pe_identity(&path)?;
                match validate_image(module, &pe) {
                    Ok(()) => {
                        matching = Some((path, pe));
                        break;
                    }
                    Err(error) => mismatches.push(format!("{}: {error}", path.display())),
                }
            }
            let (path, identity) = matching.ok_or_else(|| {
                if mismatches.is_empty() {
                    "No local matching image found.".into()
                } else {
                    mismatches.join("; ")
                }
            })?;
            report.image_path = Some(path.clone());
            let filename = wide(path.as_os_str());
            // Synthetic addresses keep reused trace image ranges independent in DbgHelp.
            let base = 0x100000000 + (index as u64) * 0x100000000;
            let loaded = unsafe {
                SymLoadModuleExW(
                    self.handle,
                    null_mut(),
                    filename.as_ptr(),
                    null(),
                    base,
                    identity.image_size,
                    null(),
                    0,
                )
            };
            if loaded == 0 {
                return Err(format!("SymLoadModuleExW: {}", unsafe { GetLastError() }));
            }
            report.symbol_base = loaded;
            let mut info = IMAGEHLP_MODULEW64 {
                SizeOfStruct: size_of::<IMAGEHLP_MODULEW64>() as u32,
                ..Default::default()
            };
            if unsafe { SymGetModuleInfoW64(self.handle, loaded, &mut info) } == 0 {
                return Err(format!("SymGetModuleInfoW64: {}", unsafe {
                    GetLastError()
                }));
            }
            if info.PdbUnmatched != 0 || info.DbgUnmatched != 0 {
                return Err("DbgHelp reported mismatched symbols.".into());
            }
            let pdb = utf16(&info.LoadedPdbName);
            if pdb.is_empty() {
                report.status = "exports_only".into();
                report.diagnostic =
                    Some("Matching PE found, but no matching local PDB was loaded.".into());
                return Ok(());
            }
            let loaded_guid = guid(&info.PdbSig70);
            if identity.pdb_guid.as_ref() != Some(&loaded_guid)
                || identity.pdb_age != Some(info.PdbAge)
            {
                return Err("Loaded PDB GUID/age does not match the PE CodeView identity.".into());
            }
            report.status = "pdb".into();
            report.pdb_path = Some(pdb);
            report.pdb_guid = Some(loaded_guid);
            report.pdb_age = Some(info.PdbAge);
            Ok(())
        })();
        if let Err(error) = result {
            report.status = "unresolved".into();
            report.diagnostic = Some(error);
        }
        report
    }

    fn resolve(&self, module: &ModuleSymbols, address: u64) -> Value {
        let offset = address - module.module.base;
        let mut frame = json!({
            "address": format!("0x{address:x}"), "module": module.module.name,
            "module_offset": format!("0x{offset:x}"), "status": module.status,
        });
        if module.status == "unresolved" {
            return frame;
        }
        let query = module.symbol_base + offset;
        let mut buffer = vec![0u64; (size_of::<SYMBOL_INFOW>() + 2048 * 2).div_ceil(8)];
        let symbol = buffer.as_mut_ptr().cast::<SYMBOL_INFOW>();
        let mut displacement = 0;
        unsafe {
            (*symbol).SizeOfStruct = size_of::<SYMBOL_INFOW>() as u32;
            (*symbol).MaxNameLen = 2048;
            if SymFromAddrW(self.handle, query, &mut displacement, symbol) == 0 {
                frame["status"] = json!("module_only");
                frame["diagnostic"] = json!(format!("SymFromAddrW: {}", GetLastError()));
                return frame;
            }
            if (*symbol).NameLen > 2048 {
                frame["status"] = json!("module_only");
                frame["diagnostic"] = json!("DbgHelp returned an oversized symbol name.");
                return frame;
            }
            let name =
                std::slice::from_raw_parts((*symbol).Name.as_ptr(), (*symbol).NameLen as usize);
            frame["function"] = json!(utf16(name));
        }
        frame["displacement"] = json!(format!("0x{displacement:x}"));
        let mut line = IMAGEHLP_LINEW64 {
            SizeOfStruct: size_of::<IMAGEHLP_LINEW64>() as u32,
            ..Default::default()
        };
        let mut line_displacement = 0;
        if unsafe { SymGetLineFromAddrW64(self.handle, query, &mut line_displacement, &mut line) }
            != 0
        {
            let mut length = 0;
            if !line.FileName.is_null() {
                unsafe {
                    while length < 32768 && *line.FileName.add(length) != 0 {
                        length += 1;
                    }
                    frame["source_file"] =
                        json!(utf16(std::slice::from_raw_parts(line.FileName, length)));
                }
                frame["source_line"] = json!(line.LineNumber);
            }
        }
        frame
    }
}

impl Drop for Symbols {
    fn drop(&mut self) {
        if unsafe { SymCleanup(self.handle) } == 0 {
            eprintln!("v8-etw: SymCleanup failed: {}", unsafe { GetLastError() });
        }
    }
}

pub fn run(output: &Path, directories: &[PathBuf], required: &[String]) -> Result<()> {
    let input = output.join("events.jsonl");
    let mut modules: Vec<Module> = Vec::new();
    let mut methods: Vec<Method> = Vec::new();
    let mut sources = BTreeMap::new();
    let mut origins: BTreeMap<(u64, u32), Origin> = BTreeMap::new();
    events(&input, |event| {
        let time = event
            .timestamp_raw
            .parse::<u64>()
            .map_err(|e| e.to_string())?;
        let p = &event.properties;
        match event.kind.as_str() {
            "image" => {
                let base = numeric(p, "ImageBase")?;
                if event.opcode == 2 {
                    if let Some(module) = modules
                        .iter_mut()
                        .rev()
                        .find(|m| m.base == base && m.unloaded_at.is_none())
                    {
                        module.unloaded_at = Some(time);
                    }
                } else {
                    let path = text(p, "FileName")?;
                    let name = path
                        .rsplit(['\\', '/'])
                        .next()
                        .ok_or("Empty image name.")?
                        .to_owned();
                    let module = Module {
                        name,
                        recorded_path: path,
                        base,
                        size: numeric(p, "ImageSize")?,
                        loaded_at: if matches!(event.opcode, 3 | 4) {
                            0
                        } else {
                            time
                        },
                        unloaded_at: None,
                        timestamp: u32::try_from(numeric(p, "TimeDateStamp")?)
                            .map_err(|e| e.to_string())?,
                        checksum: u32::try_from(numeric(p, "ImageChecksum")?)
                            .map_err(|e| e.to_string())?,
                    };
                    if !modules.iter().any(|m| {
                        m.base == module.base
                            && m.timestamp == module.timestamp
                            && m.unloaded_at.is_none()
                    }) {
                        modules.push(module);
                    }
                }
            }
            "v8_jit" if matches!(event.event_id, 41 | 39) => {
                sources.insert(
                    (numeric(p, "ScriptContextID")?, numeric(p, "SourceID")?),
                    text(p, "Url")?,
                );
            }
            "v8_jit" if matches!(event.event_id, 9 | 5) => methods.push(Method {
                base: numeric(p, "MethodStartAddress")?,
                size: numeric(p, "MethodSize")?,
                loaded_at: if event.event_id == 5 { 0 } else { time },
                name: text(p, "MethodName")?,
                source_key: (numeric(p, "ScriptContextID")?, numeric(p, "SourceID")?),
                line: numeric(p, "Line")?,
                column: numeric(p, "Column")?,
            }),
            "cpu_sample" | "virtual_memory" => {
                if origins.len() >= 5_000_000 {
                    return Err("Trace exceeds five million attribution source events; analyze a shorter capture.".into());
                }
                let origin = origins.entry((time, event.tid)).or_default();
                origin.kinds.insert(event.kind.clone());
                if event.kind == "cpu_sample" {
                    origin.cpu_samples += 1;
                } else if event.opcode == 98 {
                    origin.alloc_events += 1;
                    let flags = numeric(p, "Flags")?;
                    let size = numeric(p, "RegionSize")?;
                    if flags & 0x1000 != 0 {
                        origin.requested_commit_bytes += size;
                    }
                    if flags & 0x2000 != 0 {
                        origin.requested_reserve_bytes += size;
                    }
                } else {
                    origin.free_events += 1;
                }
            }
            _ => {}
        }
        Ok(())
    })?;
    if modules.len() > 4096 {
        return Err("Trace exceeds 4096 image lifetimes.".into());
    }
    let method_index = RangeIndex::new(methods.iter().map(|method| (method.base, method.size)));
    let module_index = RangeIndex::new(modules.iter().map(|module| (module.base, module.size)));
    eprintln!(
        "Attribution indexes: {} images, {} JIT ranges, {} source events",
        modules.len(),
        methods.len(),
        origins.len()
    );
    let symbols = Symbols::new(directories)?;
    let reports: Vec<_> = modules
        .iter()
        .enumerate()
        .map(|(i, m)| symbols.load(m, directories, i))
        .collect();
    let mut coverage: BTreeMap<String, u64> = BTreeMap::new();
    let mut cache = BTreeMap::new();
    let mut leaf_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut inclusive: BTreeMap<String, Inclusive> = BTreeMap::new();
    let mut counted: HashSet<(u64, u32, u32)> = HashSet::new();
    let mut function_ids: HashMap<String, u32> = HashMap::new();
    let mut unmatched_stacks = 0u64;
    let mut allocation_functions: BTreeMap<String, AllocationTraffic> = BTreeMap::new();
    let mut writer = BufWriter::with_capacity(
        1024 * 1024,
        File::create(output.join("symbolized.jsonl")).map_err(|e| e.to_string())?,
    );
    let started = Instant::now();
    let mut progress = Instant::now();
    let mut frame_count = 0u64;
    events(&input, |event| {
        let allocation_stack = event.kind == "heap_probe"
            && (matches!(
                event.event_name.as_str(),
                "NativeSampleAdded" | "CppgcAllocationTraffic"
            ) || (event.event_name == "CppgcLifetime"
                && numeric(&event.properties, "Kind")? == 4
                && event
                    .properties
                    .get("NativeStack")
                    .and_then(Value::as_array)
                    .is_some_and(|frames| !frames.is_empty())))
            || (event.kind == "zone_probe" && numeric(&event.properties, "Kind")? == 2);
        if !matches!(event.kind.as_str(), "cpu_sample" | "stack") && !allocation_stack {
            return Ok(());
        }
        let timestamp = if event.kind == "stack" {
            numeric(&event.properties, "EventTimeStamp")?
        } else {
            event
                .timestamp_raw
                .parse::<u64>()
                .map_err(|e| e.to_string())?
        };
        let addresses: Vec<u64> = if event.kind == "stack" || allocation_stack {
            event
                .properties
                .get(if allocation_stack {
                    "NativeStack"
                } else {
                    "Frames"
                })
                .and_then(Value::as_array)
                .ok_or("Missing stack frames.")?
                .iter()
                .map(|v| number(v).ok_or_else(|| "Invalid stack address.".into()))
                .collect::<Result<_>>()?
        } else {
            vec![numeric(&event.properties, "InstructionPointer")?]
        };
        let mut frames = Vec::new();
        let mut allocation_seen = BTreeSet::new();
        for (position, address) in addresses.into_iter().enumerate() {
            let is_return_address = allocation_stack || (event.kind == "stack" && position > 0);
            let lookup = lookup_address(address, is_return_address);
            let mut frame = if let Some(position) =
                method_at(&method_index, &methods, lookup, timestamp)
            {
                let method = &methods[position];
                json!({
                    "address": format!("0x{address:x}"), "status": "jit",
                    "function": if method.name.is_empty() { "<anonymous>" } else { &method.name },
                    "source_file": sources.get(&method.source_key),
                    "source_line": method.line, "source_column": method.column,
                    "displacement": format!("0x{:x}", lookup - method.base),
                })
            } else if let Some(index) =
                indexed_module_at(&module_index, &modules, lookup, timestamp)
            {
                cache
                    .entry((index, lookup))
                    .or_insert_with(|| symbols.resolve(&reports[index], lookup))
                    .clone()
            } else {
                json!({"address": format!("0x{address:x}"), "status": "no_image_or_jit_range"})
            };
            frame["address"] = json!(format!("0x{address:x}"));
            frame_count += 1;
            if frame_count.is_multiple_of(100_000) && progress.elapsed().as_secs() >= 10 {
                eprintln!(
                    "Symbol attribution: {frame_count} frames, {} cached PCs, {:.1}s",
                    cache.len(),
                    started.elapsed().as_secs_f64()
                );
                progress = Instant::now();
            }
            frame["lookup_address"] = json!(format!("0x{lookup:x}"));
            frame["frame_role"] = json!(if is_return_address {
                "return_address"
            } else {
                "instruction_pointer"
            });
            *coverage
                .entry(
                    frame["status"]
                        .as_str()
                        .ok_or("Invalid frame status.")?
                        .into(),
                )
                .or_default() += 1;
            if event.kind == "cpu_sample" {
                *leaf_counts.entry(function_key(&frame)).or_default() += 1;
            }
            if allocation_stack && frame.get("function").and_then(Value::as_str).is_some() {
                let domain = if event.kind == "zone_probe" {
                    format!("zone/{}", text(&event.properties, "ZoneName")?)
                } else if matches!(
                    event.event_name.as_str(),
                    "CppgcAllocationTraffic" | "CppgcLifetime"
                ) {
                    "cppgc".to_owned()
                } else {
                    text(&event.properties, "Heap")?
                };
                let key = format!("{domain}/{}", function_key(&frame));
                if allocation_seen.insert(key.clone()) {
                    let entry = allocation_functions.entry(key).or_default();
                    entry.samples += 1;
                    if event.kind == "zone_probe" {
                        entry.zone_segment_count += 1;
                        entry.zone_segment_capacity_bytes +=
                            numeric(&event.properties, "CapacityBytes")?;
                    } else if event.event_name == "CppgcLifetime" {
                        entry.exact_cppgc_allocations += 1;
                        entry.exact_cppgc_allocated_bytes +=
                            numeric(&event.properties, "AllocatedBytes")?;
                    } else if event.event_name == "CppgcAllocationTraffic" {
                        entry.sampled_requested_bytes +=
                            numeric(&event.properties, "AllocatedBytes")?;
                        entry.estimated_cppgc_traffic_bytes +=
                            numeric(&event.properties, "EstimatedTrafficBytes")?;
                    } else {
                        entry.sampled_requested_bytes +=
                            numeric(&event.properties, "RequestedBytes")?;
                        entry.estimated_native_bytes +=
                            numeric(&event.properties, "EstimatedBytes")?;
                    }
                }
            }
            if event.kind == "stack"
                && let Some(origin) = origins.get(&(timestamp, event.tid))
                && frame.get("function").and_then(Value::as_str).is_some()
            {
                let key = function_key(&frame);
                let next_id = u32::try_from(function_ids.len()).map_err(|e| e.to_string())?;
                let function_id = *function_ids.entry(key.clone()).or_insert(next_id);
                if counted.insert((timestamp, event.tid, function_id)) {
                    let entry = inclusive.entry(key).or_default();
                    entry.cpu_samples += origin.cpu_samples;
                    entry.virtual_alloc_events += origin.alloc_events;
                    entry.virtual_free_events += origin.free_events;
                    entry.requested_commit_bytes += origin.requested_commit_bytes;
                    entry.requested_reserve_bytes += origin.requested_reserve_bytes;
                }
            }
            frames.push(frame);
        }
        let related = origins.get(&(timestamp, event.tid));
        if event.kind == "stack" && related.is_none() {
            unmatched_stacks += 1;
        }
        serde_json::to_writer(
            &mut writer,
            &json!({
                "kind": event.kind, "event_name": event.event_name,
                "timestamp_raw": timestamp.to_string(), "tid": event.tid,
                "allocation_properties": if allocation_stack { Some(&event.properties) } else { None },
                "related_event_kinds": related.map(|origin| &origin.kinds), "frames": frames,
            }),
        )
        .map_err(|e| e.to_string())?;
        writer.write_all(b"\n").map_err(|e| e.to_string())
    })?;
    writer.flush().map_err(|e| e.to_string())?;
    let missing: Vec<_> = required
        .iter()
        .filter(|name| {
            !reports
                .iter()
                .any(|m| m.module.name.eq_ignore_ascii_case(name) && m.status == "pdb")
                || reports
                    .iter()
                    .any(|m| m.module.name.eq_ignore_ascii_case(name) && m.status != "pdb")
        })
        .cloned()
        .collect();
    let report = json!({
        "schema_version": 1, "symbol_directories": directories, "modules": reports,
        "frame_coverage": coverage, "cpu_leaf_sample_counts": leaf_counts,
        "inclusive_function_attribution": inclusive,
        "allocation_function_traffic": allocation_functions,
        "uncorrelated_stack_records": unmatched_stacks, "required_pdb_failures": missing,
        "limitations": [
            "Coverage counts frame occurrences, not unique addresses.",
            "JIT attribution uses observed method-load ranges; V8 does not emit a complete code-unload/move history.",
            "Native image identity uses ETL timestamp/size/checksum, then verifies the loaded PDB against PE GUID/age.",
            "Source lines are PDB mappings; inlined call chains are not expanded.",
            "Missing OS/kernel PDBs remain explicitly unresolved or exports-only; no network symbol server is used.",
            "VirtualAlloc source stacks identify allocation traffic, not per-object live memory or exact retained commit."
        ],
    });
    fs::write(
        output.join("attribution.json"),
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if !missing.is_empty() {
        return Err(format!(
            "Required matching PDBs unavailable: {}",
            missing.join(", ")
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn method(base: u64, size: u64, loaded_at: u64) -> Method {
        Method {
            base,
            size,
            loaded_at,
            name: String::new(),
            source_key: (0, 0),
            line: 0,
            column: 0,
        }
    }

    #[test]
    fn interval_lookup_matches_linear_jit_range_and_timestamp_semantics() {
        let methods = vec![
            method(100, 200, 1),
            method(150, 20, 5),
            method(150, 20, 10),
            method(170, 1, 10),
            method(150, 20, 10),
            method(u64::MAX - 1, 4, 0),
        ];
        let index = RangeIndex::new(methods.iter().map(|method| (method.base, method.size)));
        for time in [0, 1, 4, 5, 9, 10, 11] {
            for address in [0, 99, 100, 149, 150, 169, 170, 171, 299, 300, u64::MAX] {
                let linear = methods
                    .iter()
                    .enumerate()
                    .filter(|(_, method)| {
                        time >= method.loaded_at && in_range(method.base, method.size, address)
                    })
                    .max_by_key(|(_, method)| method.loaded_at)
                    .map(|(position, _)| position);
                assert_eq!(method_at(&index, &methods, address, time), linear);
            }
        }
    }

    #[test]
    fn interval_lookup_skips_nonoverlapping_ranges_and_preserves_module_lifetimes() {
        let ranges: Vec<_> = (0..26000).map(|position| (position * 1024, 64)).collect();
        let index = RangeIndex::new(ranges.iter().copied());
        assert_eq!(index.candidates(13000 * 1024 + 16).count(), 1);
        assert_eq!(index.candidates(13000 * 1024 + 64).count(), 0);
        let mut replacement = module();
        replacement.loaded_at = 21;
        replacement.unloaded_at = None;
        let modules = vec![module(), replacement];
        let index = RangeIndex::new(modules.iter().map(|module| (module.base, module.size)));
        for time in [9, 10, 19, 20, 21, 30] {
            for address in [0xfff, 0x1000, 0x10ff, 0x1100] {
                assert_eq!(
                    indexed_module_at(&index, &modules, address, time),
                    module_at(&modules, address, time)
                );
            }
        }
    }

    fn module() -> Module {
        Module {
            name: "test.exe".into(),
            recorded_path: "test.exe".into(),
            base: 0x1000,
            size: 0x100,
            loaded_at: 10,
            unloaded_at: Some(20),
            timestamp: 42,
            checksum: 7,
        }
    }

    #[test]
    fn image_lookup_respects_lifetimes_and_exclusive_range_ends() {
        let modules = vec![module()];
        assert_eq!(module_at(&modules, 0x1001, 10), Some(0));
        assert_eq!(module_at(&modules, 0x1100, 10), None);
        assert_eq!(module_at(&modules, 0x1001, 9), None);
        assert_eq!(module_at(&modules, 0x1001, 20), None);
        assert!(!in_range(u64::MAX - 1, 4, 0));
        let mut replacement = module();
        replacement.loaded_at = 21;
        replacement.unloaded_at = None;
        let reused = vec![module(), replacement];
        assert_eq!(module_at(&reused, 0x1001, 19), Some(0));
        assert_eq!(module_at(&reused, 0x1001, 20), None);
        assert_eq!(module_at(&reused, 0x1001, 21), Some(1));
    }

    #[test]
    fn recorded_image_identity_rejects_mismatches() {
        let mut pe = PeIdentity {
            timestamp: 42,
            checksum: 7,
            image_size: 0x100,
            pdb_guid: None,
            pdb_age: None,
        };
        assert!(validate_image(&module(), &pe).is_ok());
        pe.timestamp = 43;
        assert!(validate_image(&module(), &pe).is_err());
    }

    #[test]
    fn numeric_fields_preserve_addresses() {
        assert_eq!(number(&json!("0xffffffffffffffff")), Some(u64::MAX));
        assert_eq!(number(&json!({"raw_hex": "01"})), None);
    }

    #[test]
    fn caller_return_addresses_use_the_preceding_instruction() {
        assert_eq!(lookup_address(0x1100, true), 0x10ff);
        assert_eq!(lookup_address(0x1100, false), 0x1100);
        assert_eq!(lookup_address(0, true), 0);
    }

    #[test]
    fn jit_function_keys_distinguish_source_locations() {
        let first = json!({
            "status": "jit", "function": "<anonymous>", "source_file": "a.js",
            "source_line": 1, "source_column": 2,
        });
        let mut second = first.clone();
        second["source_line"] = json!(3);
        assert_ne!(function_key(&first), function_key(&second));
        assert_eq!(
            function_key(&json!({"status": "no_image_or_jit_range"})),
            "<unknown>!<unresolved>"
        );
    }
}
