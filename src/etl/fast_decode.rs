use crate::{Result, Schema, property_value};
use serde_json::{Value, json};
use std::collections::BTreeMap;

// Only used for our versioned provider's scalar, null-terminated UTF-8 and
// length-prefixed binary fields. Other providers remain on the TDH path.
pub fn probe_properties(
    bytes: &[u8],
    schema: &Schema,
    pointer_size: usize,
) -> Result<BTreeMap<String, Value>> {
    let mut cursor = 0;
    let mut values = BTreeMap::new();
    for property in &schema.properties {
        if property.structured {
            return Err("Structured field in the memory probe schema.".into());
        }
        let value =
            match property.input_type {
                2 => {
                    let tail = bytes.get(cursor..).ok_or("Probe cursor exceeds payload.")?;
                    let length = tail
                        .iter()
                        .position(|byte| *byte == 0)
                        .ok_or("Unterminated probe UTF-8 field.")?;
                    let text = std::str::from_utf8(&tail[..length]).map_err(|e| e.to_string())?;
                    cursor += length + 1;
                    json!(text)
                }
                14 => {
                    let length =
                        if let Some(name) = &property.length_property {
                            values
                                .get(name)
                                .and_then(Value::as_u64)
                                .and_then(|value| usize::try_from(value).ok())
                                .ok_or("Binary length dependency is not a decoded scalar.")?
                        } else {
                            let prefix = take(bytes, &mut cursor, 2).map_err(|error| format!(
                    "{} field {}: {error}; cursor={cursor}, payload={}; fields={:?}",
                    schema.event_name, property.name, bytes.len(),
                    schema.properties.iter().map(|p| (&p.name,p.input_type)).collect::<Vec<_>>()))?;
                            u16::from_le_bytes([prefix[0], prefix[1]]) as usize
                        };
                    let data = take(bytes, &mut cursor, length).map_err(|error| format!(
                    "{} field {}: {error}; binary length={length}, cursor={cursor}, payload={}",
                    schema.event_name, property.name, bytes.len()))?;
                    if property.name == "NativeStack" {
                        if !matches!(pointer_size, 4 | 8)
                            || !data.len().is_multiple_of(pointer_size)
                            || data.len() / pointer_size > 48
                        {
                            return Err("Invalid native probe stack frame count.".into());
                        }
                        let frames: Vec<_> = data
                            .chunks_exact(pointer_size)
                            .map(|frame| {
                                let mut word = [0u8; 8];
                                word[..pointer_size].copy_from_slice(frame);
                                format!("0x{:x}", u64::from_le_bytes(word))
                            })
                            .collect();
                        json!(frames)
                    } else {
                        let hex = data
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>();
                        json!({"raw_hex": hex})
                    }
                }
                input_type => {
                    let width = match input_type {
                        3 | 4 => 1,
                        5 | 6 => 2,
                        7 | 8 | 13 | 20 => 4,
                        9 | 10 | 17 | 21 => 8,
                        16 | 308 => pointer_size,
                        _ => {
                            return Err(format!(
                                "Unsupported memory-probe input type: {input_type}"
                            ));
                        }
                    };
                    property_value(
                        take(bytes, &mut cursor, width).map_err(|error| {
                            format!(
                                "{} field {}: {error}; width={width}, cursor={cursor}, payload={}",
                                schema.event_name,
                                property.name,
                                bytes.len()
                            )
                        })?,
                        input_type,
                        pointer_size,
                    )?
                }
            };
        values.insert(property.name.clone(), value);
    }
    if cursor != bytes.len() {
        return Err(format!(
            "Memory probe has {} undecoded payload bytes.",
            bytes.len() - cursor
        ));
    }
    Ok(values)
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .ok_or("Probe field length overflow.")?;
    let value = bytes
        .get(*cursor..end)
        .ok_or("Truncated memory probe field.")?;
    *cursor = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Property;
    use crate::heaps;
    fn schema() -> Schema {
        Schema {
            event_name: "Test".into(),
            provider: "Electron.Memory".into(),
            task: String::new(),
            opcode: String::new(),
            properties: vec![
                Property {
                    name: "Count".into(),
                    input_type: 10,
                    structured: false,
                    length_property: None,
                },
                Property {
                    name: "Name".into(),
                    input_type: 2,
                    structured: false,
                    length_property: None,
                },
                Property {
                    name: "NativeStack".into(),
                    input_type: 14,
                    structured: false,
                    length_property: None,
                },
            ],
        }
    }
    #[test]
    fn decodes_scalar_utf8_and_empty_binary_without_tdh() {
        let mut bytes = 42u64.to_le_bytes().to_vec();
        bytes.extend_from_slice(b"heap\0\0\0");
        let values = probe_properties(&bytes, &schema(), 8).unwrap();
        assert_eq!(values["Count"], 42);
        assert_eq!(values["Name"], "heap");
        assert_eq!(values["NativeStack"], json!([]));
        let hex = "3412000000000000";
        let mut bytes = 42u64.to_le_bytes().to_vec();
        bytes.extend_from_slice(b"heap\0\x08\0");
        bytes.extend_from_slice(&0x1234u64.to_le_bytes());
        assert_eq!(
            probe_properties(&bytes, &schema(), 8).unwrap()["NativeStack"],
            heaps::stack_frames(hex).unwrap()
        );
    }
    #[test]
    fn rejects_truncation_extra_bytes_and_bad_utf8() {
        assert!(probe_properties(&[0; 7], &schema(), 8).is_err());
        let mut bytes = 42u64.to_le_bytes().to_vec();
        bytes.extend_from_slice(b"heap\0\0\0\x01");
        assert!(probe_properties(&bytes, &schema(), 8).is_err());
        bytes.truncate(8);
        bytes.extend_from_slice(b"\xff\0\0\0");
        assert!(probe_properties(&bytes, &schema(), 8).is_err());
    }

    #[test]
    fn honors_tdh_expanded_binary_length_dependency() {
        let mut schema = schema();
        schema.properties.insert(
            2,
            Property {
                name: "NativeStack.Length".into(),
                input_type: 6,
                structured: false,
                length_property: None,
            },
        );
        schema.properties[3].length_property = Some("NativeStack.Length".into());
        let mut bytes = 42u64.to_le_bytes().to_vec();
        bytes.extend_from_slice(b"heap\0\x08\0");
        bytes.extend_from_slice(&0x1234u64.to_le_bytes());
        let values = probe_properties(&bytes, &schema, 8).unwrap();
        assert_eq!(values["NativeStack.Length"], 8);
        assert_eq!(values["NativeStack"], json!(["0x1234"]));
        bytes.truncate(15);
        bytes[13] = 0;
        assert_eq!(
            probe_properties(&bytes, &schema, 8).unwrap()["NativeStack"],
            json!([])
        );
    }
}
