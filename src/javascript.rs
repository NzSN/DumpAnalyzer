//! Bounded projections of Forensicator's V8/JIT observations. These remain
//! citable query evidence; they never replace the native stack or change the
//! canonical report schema. Frame classification is the upstream observation,
//! not proof of a complete stack, an inlined frame, or a crash cause.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{Value, json};

pub(crate) const KIND: &str = "forensicator.javascriptStack.v1";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Options {
    pub thread_id: Option<u32>,
    #[serde(default = "default_frames")]
    pub max_frames: u8,
    #[serde(default)]
    pub include_jit: bool,
    pub symbols: Option<String>,
}

fn default_frames() -> u8 {
    16
}

#[derive(Deserialize)]
struct V8Frame {
    thread_id: u32,
    depth: u32,
    frame_type: String,
    return_address: String,
    frame_pointer: String,
    js_function_name: Option<String>,
    script_name: Option<String>,
    script_line: Option<u32>,
}

pub(crate) struct Projection {
    pub text: String,
    pub truncated: bool,
}

const INVALID: &str = "Forensicator returned invalid V8/JIT frame data";
type Result<T> = std::result::Result<T, &'static str>;

fn custom<'a>(report: &'a Value, name: &str) -> Result<BTreeMap<&'a str, &'a Value>> {
    let plugins = report
        .get("plugins")
        .and_then(Value::as_array)
        .ok_or(INVALID)?;
    let mut selected = plugins
        .iter()
        .filter(|plugin| plugin["name"].as_str() == Some(name));
    let plugin = selected.next().ok_or(INVALID)?;
    if selected.next().is_some() {
        return Err(INVALID);
    }
    let mut fields = BTreeMap::new();
    for entry in plugin
        .get("custom")
        .and_then(Value::as_array)
        .ok_or(INVALID)?
    {
        let object = entry.as_object().ok_or(INVALID)?;
        if object.len() != 1 {
            return Err(INVALID);
        }
        for (key, value) in object {
            if fields.insert(key.as_str(), value).is_some() {
                return Err(INVALID);
            }
        }
    }
    Ok(fields)
}

fn address(value: &str) -> Result<String> {
    let hex = value.strip_prefix("0x").ok_or(INVALID)?;
    if hex.is_empty() || hex.len() > 16 || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(INVALID);
    }
    Ok(format!(
        "0x{:x}",
        u64::from_str_radix(hex, 16).map_err(|_| INVALID)?
    ))
}

fn optional_address(value: &Value) -> Result<Value> {
    if value.is_null() {
        Ok(Value::Null)
    } else {
        Ok(json!(address(value.as_str().ok_or(INVALID)?)?))
    }
}

fn bounded(text: Option<&str>, limit: usize, shortened: &mut bool) -> Value {
    match text {
        None => Value::Null,
        Some(text) => {
            let mut end = limit.min(text.len());
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            *shortened |= end != text.len();
            json!(&text[..end])
        }
    }
}

fn jit_summary(value: &Value, shortened: &mut bool) -> Result<Value> {
    let code = &value["code_resolution"];
    // The release formats some numeric JIT fields with a misleading "0x"
    // prefix over decimal digits. Do not reinterpret dispatch_handle or
    // native_offset as addresses. Only the actual hexUpper address fields
    // enter this projection; caller-code lookup remains an upstream heuristic.
    let code = if code.is_null() {
        Value::Null
    } else {
        if !code.is_object() {
            return Err(INVALID);
        }
        json!({
            "entrypoint":optional_address(&code["entrypoint"] )?,
            "codeObject":optional_address(&code["code_object"] )?,
            "framePc":optional_address(&code["return_address"] )?,
            "callerCodeObject":optional_address(&code["caller_code_object"] )?
        })
    };
    Ok(json!({
        "feedbackVector":optional_address(&value["feedback_vector"] )?,
        "slotCount":value["slot_count"].as_u64().ok_or(INVALID)?,
        "sfiCrosscheck":value["sfi_crosscheck"].as_bool().ok_or(INVALID)?,
        "feedbackPath":bounded(value["feedback_path"].as_str(), 256, shortened),
        "codeResolution":code
    }))
}

pub(crate) fn project(text: &str, options: &Options, cap: usize) -> Result<Projection> {
    let report: Value = serde_json::from_str(text).map_err(|_| INVALID)?;
    let v8 = custom(&report, "v8")?;
    let frames = v8
        .get("v8_frames")
        .and_then(|v| v.as_array())
        .ok_or(INVALID)?;
    if v8.get("v8_frame_count").and_then(|v| v.as_u64()) != Some(frames.len() as u64) {
        return Err(INVALID);
    }
    let heap = v8
        .get("v8_heap_captured")
        .and_then(|v| v.as_bool())
        .ok_or(INVALID)?;
    let mut jit_frames = BTreeMap::new();
    if options.include_jit {
        let jit = custom(&report, "jit")?;
        let entries = jit
            .get("jit_frames")
            .and_then(|v| v.as_array())
            .ok_or(INVALID)?;
        if jit.get("jit_frame_count").and_then(|v| v.as_u64()) != Some(entries.len() as u64) {
            return Err(INVALID);
        }
        for entry in entries {
            let tid = entry["thread_id"]
                .as_u64()
                .filter(|v| *v <= u32::MAX as u64)
                .ok_or(INVALID)? as u32;
            let depth = entry["depth"]
                .as_u64()
                .filter(|v| *v < 256)
                .ok_or(INVALID)? as u32;
            if jit_frames.insert((tid, depth), entry).is_some() {
                return Err(INVALID);
            }
        }
    }
    let mut projected = Vec::new();
    let mut identities = BTreeMap::new();
    let mut candidates = 0;
    let mut recovered = 0;
    let mut optimized = 0;
    let mut selected_frames = 0;
    let mut shortened = false;
    for value in frames {
        let frame: V8Frame = serde_json::from_value(value.clone()).map_err(|_| INVALID)?;
        if frame.depth >= 256
            || frame.frame_type.len() > 64
            || frame.script_line == Some(0)
            || identities
                .insert((frame.thread_id, frame.depth), ())
                .is_some()
        {
            return Err(INVALID);
        }
        if options.thread_id.is_some_and(|id| id != frame.thread_id) {
            continue;
        }
        selected_frames += 1;
        let has_metadata = frame
            .js_function_name
            .as_ref()
            .is_some_and(|s| !s.is_empty());
        if !has_metadata
            && !matches!(
                frame.frame_type.as_str(),
                "JavaScript" | "OptimizedJavaScript"
            )
        {
            continue;
        }
        candidates += 1;
        recovered += usize::from(has_metadata);
        optimized += usize::from(has_metadata && frame.frame_type == "OptimizedJavaScript");
        if projected.len() >= options.max_frames as usize {
            continue;
        }
        let jit = if let Some(jit) = jit_frames.get(&(frame.thread_id, frame.depth)) {
            if jit["function_name"].as_str() != frame.js_function_name.as_deref()
                || jit["script_name"].as_str() != frame.script_name.as_deref()
                || jit["script_line"].as_u64() != frame.script_line.map(u64::from)
            {
                return Err(INVALID);
            }
            if let Some(pc) = jit.pointer("/code_resolution/return_address") {
                if address(pc.as_str().ok_or(INVALID)?)? != address(&frame.return_address)? {
                    return Err(INVALID);
                }
            }
            jit_summary(jit, &mut shortened)?
        } else {
            Value::Null
        };
        projected.push(json!({
            "threadId":frame.thread_id, "depth":frame.depth, "frameType":frame.frame_type,
            "framePc":address(&frame.return_address)?, "framePointer":address(&frame.frame_pointer)?,
            "function":bounded(frame.js_function_name.as_deref(), 256, &mut shortened),
            "script":bounded(frame.script_name.as_deref(), 512, &mut shortened),
            "functionStartLine":frame.script_line, "metadataRecovered":has_metadata, "jit":jit
        }));
    }
    let unavailable = match v8.get("v8_unavailable_threads") {
        None => &[][..],
        Some(value) => value.as_array().ok_or(INVALID)?.as_slice(),
    };
    let mut unavailable_ids = Vec::new();
    for thread in unavailable {
        let tid = thread["thread_id"]
            .as_u64()
            .filter(|v| *v <= u32::MAX as u64)
            .ok_or(INVALID)? as u32;
        if options.thread_id.is_none_or(|id| id == tid) {
            unavailable_ids.push(tid);
        }
    }
    let unavailable_count = unavailable_ids.len();
    unavailable_ids.truncate(16);
    let mut limitations = vec![
        "Physical frames only; inlined logical frames, async ancestry and complete stack coverage are not recovered.",
        "Source lines identify function starts, not exact executing statements or call sites.",
        "Frame kinds and names are Forensicator observations using its V8 layout heuristics; verify the runtime version and captured memory.",
        "A mapped cage page does not establish complete V8 heap capture.",
    ];
    if !heap {
        limitations.push("V8 heap coverage was not established; missing cage annotations or memory can prevent recovery.");
    }
    if recovered == 0 {
        limitations.push("No JavaScript function metadata was recovered. This does not prove JavaScript frames were absent.");
    }
    if candidates > recovered {
        limitations.push("Some frame kinds suggest JavaScript but lack recovered function metadata; treat them as unresolved candidates.");
    }
    if unavailable_count > 0 {
        limitations
            .push("Some threads lack the register context or stack bounds needed for recovery.");
    }
    if options.include_jit {
        limitations.push("JIT code/feedback recovery is optional and may be unavailable; it does not reconstruct inline frames or prove optimization caused the crash.");
    }
    if shortened {
        limitations
            .push("Some names or metadata strings were shortened to fit the evidence budget.");
    }
    let mut result = json!({
        "kind":KIND, "threadId":options.thread_id, "includeJit":options.include_jit,
        "heapCaptured":heap, "sourceFrameCount":frames.len(), "selectedThreadFrameCount":selected_frames,
        "candidateFrameCount":candidates, "recoveredFrameCount":recovered,
        "optimizedFrameCount":optimized, "omittedFrameCount":candidates - projected.len(),
        "unavailableThreadCount":unavailable_count, "unavailableThreadIds":unavailable_ids,
        "frames":projected, "limitations":limitations
    });
    loop {
        let text = serde_json::to_string(&result).map_err(|_| INVALID)?;
        if text.len() <= cap {
            return Ok(Projection {
                text,
                truncated: shortened || result["omittedFrameCount"] != 0 || unavailable_count > 16,
            });
        }
        if result["frames"]
            .as_array_mut()
            .ok_or(INVALID)?
            .pop()
            .is_none()
        {
            return Err("Insufficient evidence budget for the JavaScript recovery summary");
        }
        result["omittedFrameCount"] =
            json!(candidates - result["frames"].as_array().ok_or(INVALID)?.len());
    }
}
