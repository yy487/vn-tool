use crate::font::{self, EncodingPlan, EncodingPlanEntry};
use crate::{
    commit_output, hex_encode, is_drrnger_system_disk, parse_d88, parse_resource_table,
    reject_output_containing_inputs, resource_slice, safe_output_segment, scenario_native_size,
    sha256_hex, temporary_sibling, validate_drrnger_pair, ParsedDisk, ResourceEntry,
};
use anyhow::{bail, Context, Result};
use encoding_rs::EUC_JP;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

const WORKSPACE_FORMAT: &str = "drrnger-localization-workspace-v1";
const DOCUMENT_FORMAT: &str = "drrnger-indexed-text-v1";
const REBUILD_FORMAT: &str = "drrnger-localization-rebuild-v1";
const COMMON_POOL_OFFSET: usize = 0x0780;
const COMMON_STRING_COUNT: usize = 23;
const SECTOR_SIZE: usize = 256;
const GRAPHICS_TABLE_OFFSET: usize = 0x1410;
const SCENARIO_TABLE_OFFSET: usize = 0x1690;
const VNCOM_OFFSET: usize = 0x0400;
const VNCOM_SIZE: usize = 0x1000;

const OPCODE_LENGTHS: [usize; 41] = [
    0x06, 0x06, 0x09, 0x09, 0x09, 0x09, 0x06, 0x0B, 0x0B, 0x0B, 0x09, 0x09, 0x09, 0x09, 0x0C, 0x0C,
    0x0C, 0x0C, 0x04, 0x08, 0x06, 0x10, 0x10, 0x10, 0x10, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E,
    0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E,
];

#[derive(Debug, Clone)]
pub struct LocalizationExtractReport {
    pub documents: usize,
    pub entries: usize,
    pub references: usize,
    pub preserved_translations: usize,
    pub output: PathBuf,
}

#[derive(Debug, Clone)]
pub struct LocalizationPackReport {
    pub entries: usize,
    pub changed_entries: usize,
    pub changed_scenarios: usize,
    pub relocated_scenarios: usize,
    pub redrawn_slots: usize,
    pub output: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalizationManifest {
    #[serde(rename = "_format")]
    format: String,
    tool_version: String,
    sources: Vec<LocalizationSource>,
    documents: Vec<DocumentReference>,
    profile: String,
    summary: LocalizationSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalizationSource {
    role: String,
    source_file: String,
    source_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DocumentReference {
    kind: String,
    scene_index: Option<usize>,
    json_file: String,
    source_file: String,
    source_sha256: String,
    allocation_sha256: Option<String>,
    entries: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalizationSummary {
    disks: usize,
    documents: usize,
    entries: usize,
    references: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TextDocument {
    #[serde(rename = "_format")]
    format: String,
    #[serde(rename = "_kind")]
    kind: String,
    #[serde(rename = "_source_file")]
    source_file: String,
    #[serde(rename = "_source_sha256")]
    source_sha256: String,
    #[serde(rename = "_allocation_sha256", skip_serializing_if = "Option::is_none")]
    allocation_sha256: Option<String>,
    #[serde(rename = "_scene_index", skip_serializing_if = "Option::is_none")]
    scene_index: Option<usize>,
    #[serde(rename = "_string_pool_offset")]
    string_pool_offset: usize,
    #[serde(rename = "_indexed_end")]
    indexed_end: usize,
    entries: Vec<TextEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TextEntry {
    #[serde(rename = "_index")]
    index: usize,
    #[serde(rename = "_pool_index")]
    pool_index: usize,
    #[serde(rename = "_offset")]
    offset: usize,
    #[serde(rename = "_size")]
    size: usize,
    #[serde(rename = "_encoding")]
    encoding: String,
    #[serde(rename = "_source_bytes_hex")]
    source_bytes_hex: String,
    #[serde(rename = "_message_codes")]
    message_codes: Vec<String>,
    references: Vec<TextReference>,
    scr_msg: String,
    message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TextReference {
    scene_index: usize,
    command_offset: usize,
    event_key: u16,
    opcode: u8,
    opcode_hex: String,
    field_offset: usize,
    branch: String,
    slot: usize,
    code_hex: String,
}

#[derive(Debug, Clone)]
struct InputPair {
    prepared: Vec<(PathBuf, String, ParsedDisk)>,
    system_index: usize,
    other_index: usize,
    scenarios: Vec<ResourceEntry>,
}

#[derive(Debug, Clone)]
struct StringSpan {
    start: usize,
    end: usize,
    text: String,
}

#[derive(Debug, Clone)]
enum MessageTarget {
    Common(usize),
    Scene(usize),
}

#[derive(Debug, Clone)]
struct MessageUse {
    target: MessageTarget,
    reference: TextReference,
}

#[derive(Debug, Clone, Copy)]
struct MessageField {
    offset: usize,
    branch: &'static str,
    slot: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TranslationKey {
    kind: String,
    scene_index: Option<usize>,
    pool_index: usize,
    scr_msg: String,
}

#[derive(Debug, Clone, Serialize)]
struct RebuildManifest {
    #[serde(rename = "_format")]
    format: String,
    tool_version: String,
    disks: Vec<RebuiltDisk>,
    font: RebuiltFont,
    resources: Vec<RebuiltResource>,
    summary: RebuildSummary,
}

#[derive(Debug, Clone, Serialize)]
struct RebuiltDisk {
    role: String,
    source_file: String,
    source_sha256: String,
    output_file: String,
    output_sha256: String,
    changed: bool,
}

#[derive(Debug, Clone, Serialize)]
struct RebuiltFont {
    output_file: String,
    sha256: String,
    face: String,
    redrawn_slots: usize,
    mappings: Vec<EncodingPlanEntry>,
}

#[derive(Debug, Clone, Serialize)]
struct RebuiltResource {
    scene_index: usize,
    disk_number: u8,
    changed_entries: usize,
    native_bytes: usize,
    original_start_sector: u16,
    original_sector_count: u16,
    output_start_sector: u16,
    output_sector_count: u16,
    relocated: bool,
    output_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct RebuildSummary {
    entries: usize,
    changed_entries: usize,
    changed_scenarios: usize,
    relocated_scenarios: usize,
}

pub fn extract_localization(
    inputs: &[PathBuf],
    output: &Path,
    overwrite: bool,
) -> Result<LocalizationExtractReport> {
    reject_output_containing_inputs(inputs, output)?;
    validate_managed_output(output, overwrite, WORKSPACE_FORMAT, "workspace.json")?;
    let previous = if overwrite && output.join("workspace.json").is_file() {
        read_translation_memory(output)?
    } else {
        HashMap::new()
    };
    let pair = load_pair(inputs)?;
    let system = &pair.prepared[pair.system_index].2;
    let other = &pair.prepared[pair.other_index].2;
    let disks = [system, other];

    let staging = temporary_sibling(output)?;
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    fs::create_dir_all(staging.join("translation_json"))?;
    fs::create_dir_all(staging.join("profile"))?;

    let mut common_references = vec![Vec::<TextReference>::new(); COMMON_STRING_COUNT];
    let mut documents = Vec::with_capacity(pair.scenarios.len() + 1);
    let mut total_entries = 0usize;
    let mut total_references = 0usize;
    let mut preserved_translations = 0usize;

    for (scene_index, directory) in pair.scenarios.iter().enumerate() {
        let allocation = resource_slice(directory, &disks)?;
        let native = &allocation[..scenario_native_size(allocation)];
        let uses = parse_scene_message_uses(native, scene_index)?;
        let scene_count = uses
            .iter()
            .filter_map(|item| match item.target {
                MessageTarget::Scene(index) => Some(index + 1),
                MessageTarget::Common(_) => None,
            })
            .max()
            .unwrap_or(0);
        let pool_offset = 0x4Cusize
            .checked_add(usize::from(read_u16(native, 0x4A)?))
            .context("scene string-pool offset overflow")?;
        let spans = parse_string_spans(native, pool_offset, scene_count)
            .with_context(|| format!("SC{scene_index:03}.DSC string pool"))?;
        let mut refs_by_index = vec![Vec::new(); scene_count];
        for usage in uses {
            match usage.target {
                MessageTarget::Common(index) => {
                    common_references[index].push(usage.reference);
                }
                MessageTarget::Scene(index) => {
                    refs_by_index[index].push(usage.reference);
                }
            }
        }
        let mut entries = Vec::with_capacity(spans.len());
        for (index, span) in spans.iter().enumerate() {
            let key = TranslationKey {
                kind: "scenario".to_owned(),
                scene_index: Some(scene_index),
                pool_index: index,
                scr_msg: span.text.clone(),
            };
            let message = previous
                .get(&key)
                .cloned()
                .unwrap_or_else(|| span.text.clone());
            preserved_translations += usize::from(previous.contains_key(&key));
            total_references += refs_by_index[index].len();
            entries.push(make_entry(
                index,
                span,
                vec![format!("0x{:02X}", decimal_to_bcd(index + 13)?)],
                std::mem::take(&mut refs_by_index[index]),
                message,
                native,
            ));
        }
        let source_file = format!("SC{scene_index:03}.DSC");
        let source_sha256 = sha256_hex(native);
        let allocation_sha256 = sha256_hex(allocation);
        let document = TextDocument {
            format: DOCUMENT_FORMAT.to_owned(),
            kind: "scenario".to_owned(),
            source_file: source_file.clone(),
            source_sha256: source_sha256.clone(),
            allocation_sha256: Some(allocation_sha256.clone()),
            scene_index: Some(scene_index),
            string_pool_offset: pool_offset,
            indexed_end: spans.last().map_or(pool_offset, |span| span.end),
            entries,
        };
        let json_file = format!("translation_json/SC{scene_index:03}.json");
        write_json(&staging.join(&json_file), &document)?;
        total_entries += document.entries.len();
        documents.push(DocumentReference {
            kind: document.kind,
            scene_index: document.scene_index,
            json_file,
            source_file,
            source_sha256,
            allocation_sha256: Some(allocation_sha256),
            entries: document.entries.len(),
        });
    }

    let vncom = system
        .logical
        .get(VNCOM_OFFSET..VNCOM_OFFSET + VNCOM_SIZE)
        .context("system disk lacks VNCOM.BIN range")?;
    let common_spans = parse_string_spans(vncom, COMMON_POOL_OFFSET, COMMON_STRING_COUNT)?;
    let mut common_entries = Vec::with_capacity(COMMON_STRING_COUNT);
    for (index, span) in common_spans.iter().enumerate() {
        let key = TranslationKey {
            kind: "common".to_owned(),
            scene_index: None,
            pool_index: index,
            scr_msg: span.text.clone(),
        };
        let message = previous
            .get(&key)
            .cloned()
            .unwrap_or_else(|| span.text.clone());
        preserved_translations += usize::from(previous.contains_key(&key));
        total_references += common_references[index].len();
        common_entries.push(make_entry(
            index,
            span,
            common_codes(index)?,
            std::mem::take(&mut common_references[index]),
            message,
            vncom,
        ));
    }
    let common_sha256 = sha256_hex(vncom);
    let common_document = TextDocument {
        format: DOCUMENT_FORMAT.to_owned(),
        kind: "common".to_owned(),
        source_file: "VNCOM.BIN".to_owned(),
        source_sha256: common_sha256.clone(),
        allocation_sha256: None,
        scene_index: None,
        string_pool_offset: COMMON_POOL_OFFSET,
        indexed_end: common_spans
            .last()
            .map_or(COMMON_POOL_OFFSET, |span| span.end),
        entries: common_entries,
    };
    write_json(
        &staging.join("translation_json/common.json"),
        &common_document,
    )?;
    total_entries += common_document.entries.len();
    documents.insert(
        0,
        DocumentReference {
            kind: "common".to_owned(),
            scene_index: None,
            json_file: "translation_json/common.json".to_owned(),
            source_file: "VNCOM.BIN".to_owned(),
            source_sha256: common_sha256,
            allocation_sha256: None,
            entries: common_document.entries.len(),
        },
    );

    let sources = vec![
        source_manifest(&pair, pair.system_index, "A")?,
        source_manifest(&pair, pair.other_index, "B")?,
    ];
    let manifest = LocalizationManifest {
        format: WORKSPACE_FORMAT.to_owned(),
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        sources,
        documents,
        profile: "profile/project.json".to_owned(),
        summary: LocalizationSummary {
            disks: 2,
            documents: pair.scenarios.len() + 1,
            entries: total_entries,
            references: total_references,
        },
    };
    write_json(&staging.join("workspace.json"), &manifest)?;
    write_profile(&staging.join("profile/project.json"))?;
    commit_output(&staging, output, overwrite)?;

    Ok(LocalizationExtractReport {
        documents: manifest.summary.documents,
        entries: total_entries,
        references: total_references,
        preserved_translations,
        output: output.to_path_buf(),
    })
}

pub fn pack_localization(
    inputs: &[PathBuf],
    workspace: &Path,
    output: &Path,
    overwrite: bool,
) -> Result<LocalizationPackReport> {
    reject_output_containing_inputs(inputs, output)?;
    validate_managed_output(output, overwrite, REBUILD_FORMAT, "rebuild_manifest.json")?;
    let manifest: LocalizationManifest = read_json(&workspace.join("workspace.json"))?;
    if manifest.format != WORKSPACE_FORMAT {
        bail!("workspace.json is not a Drrnger localization workspace");
    }
    let pair = load_pair(inputs)?;
    match_workspace_sources(&pair, &manifest)?;
    let documents = load_documents(workspace, &manifest)?;
    let common_document = documents
        .iter()
        .find(|document| document.kind == "common")
        .context("localization workspace has no common document")?;
    let mut scene_documents = vec![None; pair.scenarios.len()];
    for document in &documents {
        if document.kind != "scenario" {
            continue;
        }
        let index = document
            .scene_index
            .context("scenario document lacks scene index")?;
        let slot = scene_documents
            .get_mut(index)
            .context("scenario document index is outside directory")?;
        if slot.replace(document).is_some() {
            bail!("duplicate scenario document SC{index:03}");
        }
    }
    if scene_documents.iter().any(Option::is_none) {
        bail!("localization workspace does not contain all 57 scenario documents");
    }

    let system = &pair.prepared[pair.system_index].2;
    let other = &pair.prepared[pair.other_index].2;
    let disks = [system, other];
    let vncom = system
        .logical
        .get(VNCOM_OFFSET..VNCOM_OFFSET + VNCOM_SIZE)
        .context("system disk lacks VNCOM.BIN range")?;

    let mut plan_texts = documents
        .iter()
        .flat_map(|document| document.entries.iter().map(|entry| entry.message.clone()))
        .collect::<Vec<_>>();
    plan_texts.push(protected_vncom_characters(vncom)?);
    let plan =
        EncodingPlan::build(plan_texts.iter().map(String::as_str)).map_err(anyhow::Error::msg)?;
    let font_build =
        font::prepare_font(&plan.requests(), &BTreeSet::new()).map_err(anyhow::Error::msg)?;

    let (rebuilt_vncom, common_changed) = rebuild_common(vncom, common_document, &plan)?;
    let mut rebuilt_scenarios = Vec::with_capacity(pair.scenarios.len());
    let mut changed_entries = common_changed;
    let mut changed_scenarios = 0usize;
    for (index, (directory, document)) in pair
        .scenarios
        .iter()
        .zip(scene_documents.into_iter())
        .enumerate()
    {
        let document = document.expect("checked complete scenario document set");
        let allocation = resource_slice(directory, &disks)?;
        let native = &allocation[..scenario_native_size(allocation)];
        let (rebuilt, changed) = rebuild_document(native, document, &plan)?;
        changed_entries += changed;
        changed_scenarios += usize::from(changed != 0);
        rebuilt_scenarios.push((index, rebuilt, changed));
    }

    let mut logical = pair
        .prepared
        .iter()
        .map(|(_, _, disk)| disk.logical.clone())
        .collect::<Vec<_>>();
    if common_changed != 0 {
        logical[pair.system_index][VNCOM_OFFSET..VNCOM_OFFSET + VNCOM_SIZE]
            .copy_from_slice(&rebuilt_vncom);
    }
    let mut append = [
        first_trailing_zero_sector(&logical[pair.system_index]),
        first_trailing_zero_sector(&logical[pair.other_index]),
    ];
    let mut rebuilt_resources = Vec::new();
    let mut changed_resource_bytes = Vec::new();
    let mut relocated_scenarios = 0usize;
    for (index, rebuilt, changed) in rebuilt_scenarios {
        let directory = &pair.scenarios[index];
        let runtime_disk = usize::from(directory.disk_number - 1);
        let input_index = if runtime_disk == 0 {
            pair.system_index
        } else {
            pair.other_index
        };
        let original_start = usize::from(directory.start_sector);
        let original_count = usize::from(directory.sector_count);
        let required = rebuilt.len().div_ceil(SECTOR_SIZE);
        let (output_start, output_count, relocated) = if changed == 0 {
            (original_start, original_count, false)
        } else if required <= original_count {
            write_sector_allocation(
                &mut logical[input_index],
                original_start,
                original_count,
                &rebuilt,
            )?;
            (original_start, original_count, false)
        } else {
            let start = append[runtime_disk];
            let end = start
                .checked_add(required)
                .context("relocated scene sector range overflow")?;
            if end > logical[input_index].len() / SECTOR_SIZE {
                bail!(
                    "SC{index:03}.DSC needs {required} sectors but disk {} has only {} trailing sectors",
                    directory.disk_number,
                    logical[input_index].len() / SECTOR_SIZE - start
                );
            }
            write_sector_allocation(&mut logical[input_index], start, required, &rebuilt)?;
            append[runtime_disk] = end;
            relocated_scenarios += 1;
            (start, required, true)
        };
        if changed != 0 {
            write_directory_entry(
                &mut logical[pair.system_index],
                directory.table_offset,
                output_start,
                output_count,
            )?;
            changed_resource_bytes.push((index, rebuilt.clone()));
        }
        rebuilt_resources.push(RebuiltResource {
            scene_index: index,
            disk_number: directory.disk_number,
            changed_entries: changed,
            native_bytes: rebuilt.len(),
            original_start_sector: directory.start_sector,
            original_sector_count: directory.sector_count,
            output_start_sector: u16::try_from(output_start).context("sector number overflow")?,
            output_sector_count: u16::try_from(output_count).context("sector count overflow")?,
            relocated,
            output_sha256: sha256_hex(&rebuilt),
        });
    }

    let staging = temporary_sibling(output)?;
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    fs::create_dir_all(staging.join("rebuilt_resources"))?;
    let write_result = (|| -> Result<RebuildManifest> {
        fs::write(staging.join("font.tmp"), &font_build.bytes)?;
        fs::write(staging.join("VNCOM.BIN"), &rebuilt_vncom)?;
        fs::write(
            staging.join("DIRBLK.BIN"),
            &logical[pair.system_index][0x1410..0x1910],
        )?;
        for (scene_index, bytes) in &changed_resource_bytes {
            let path = staging
                .join("rebuilt_resources")
                .join(format!("SC{scene_index:03}.DSC"));
            fs::write(path, bytes)?;
        }

        let mut disk_results = Vec::with_capacity(2);
        for (input_index, role) in [(pair.system_index, "A"), (pair.other_index, "B")] {
            let source = &pair.prepared[input_index];
            let rebuilt = logical_to_d88(&source.2, &logical[input_index])?;
            let source_file = source
                .0
                .file_name()
                .context("D88 input has no filename")?
                .to_string_lossy()
                .into_owned();
            fs::write(staging.join(&source_file), &rebuilt)?;
            disk_results.push(RebuiltDisk {
                role: role.to_owned(),
                source_file: source_file.clone(),
                source_sha256: sha256_hex(&source.2.bytes),
                output_file: source_file,
                output_sha256: sha256_hex(&rebuilt),
                changed: rebuilt != source.2.bytes,
            });
        }
        let rebuild = RebuildManifest {
            format: REBUILD_FORMAT.to_owned(),
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            disks: disk_results,
            font: RebuiltFont {
                output_file: "font.tmp".to_owned(),
                sha256: sha256_hex(&font_build.bytes),
                face: font::FONT_FACE.to_owned(),
                redrawn_slots: font_build.patched_glyphs,
                mappings: plan.manifest_entries().map_err(anyhow::Error::msg)?,
            },
            resources: rebuilt_resources.clone(),
            summary: RebuildSummary {
                entries: documents
                    .iter()
                    .map(|document| document.entries.len())
                    .sum(),
                changed_entries,
                changed_scenarios,
                relocated_scenarios,
            },
        };
        write_json(&staging.join("rebuild_manifest.json"), &rebuild)?;
        Ok(rebuild)
    })();
    let rebuild = match write_result {
        Ok(value) => value,
        Err(error) => {
            let _ = fs::remove_dir_all(&staging);
            return Err(error);
        }
    };
    commit_output(&staging, output, overwrite)?;
    Ok(LocalizationPackReport {
        entries: rebuild.summary.entries,
        changed_entries: rebuild.summary.changed_entries,
        changed_scenarios: rebuild.summary.changed_scenarios,
        relocated_scenarios: rebuild.summary.relocated_scenarios,
        redrawn_slots: rebuild.font.redrawn_slots,
        output: output.to_path_buf(),
    })
}

fn load_pair(inputs: &[PathBuf]) -> Result<InputPair> {
    if inputs.len() != 2 {
        bail!("Drrnger localization requires exactly two D88 inputs");
    }
    let mut prepared = Vec::with_capacity(2);
    let mut names = HashSet::new();
    for input in inputs {
        let bytes = fs::read(input)
            .with_context(|| format!("failed to read D88 image {}", input.display()))?;
        let parsed = parse_d88(bytes)
            .with_context(|| format!("failed to parse D88 image {}", input.display()))?;
        let label = safe_output_segment(
            &input
                .file_stem()
                .or_else(|| input.file_name())
                .context("D88 input has no filename")?
                .to_string_lossy(),
        );
        if !names.insert(label.to_ascii_uppercase()) {
            bail!("D88 inputs have colliding output names");
        }
        prepared.push((input.clone(), label, parsed));
    }
    validate_drrnger_pair(&prepared)?;
    let system_index = prepared
        .iter()
        .position(|(_, _, disk)| is_drrnger_system_disk(&disk.logical))
        .context("Drrnger system disk was not found")?;
    let other_index = 1 - system_index;
    let system = &prepared[system_index].2.logical;
    let _graphics = parse_resource_table(system, GRAPHICS_TABLE_OFFSET)?;
    let scenarios = parse_resource_table(system, SCENARIO_TABLE_OFFSET)?;
    Ok(InputPair {
        prepared,
        system_index,
        other_index,
        scenarios,
    })
}

fn source_manifest(pair: &InputPair, index: usize, role: &str) -> Result<LocalizationSource> {
    let source = &pair.prepared[index];
    Ok(LocalizationSource {
        role: role.to_owned(),
        source_file: source
            .0
            .file_name()
            .context("D88 input has no filename")?
            .to_string_lossy()
            .into_owned(),
        source_sha256: sha256_hex(&source.2.bytes),
    })
}

fn make_entry(
    index: usize,
    span: &StringSpan,
    message_codes: Vec<String>,
    references: Vec<TextReference>,
    message: String,
    source: &[u8],
) -> TextEntry {
    TextEntry {
        index,
        pool_index: index,
        offset: span.start,
        size: span.end - span.start,
        encoding: "little-endian JIS X 0208, 0000 terminator".to_owned(),
        source_bytes_hex: hex_encode(&source[span.start..span.end]),
        message_codes,
        references,
        scr_msg: span.text.clone(),
        message,
    }
}

fn common_codes(index: usize) -> Result<Vec<String>> {
    let decimal = if index <= 12 { index } else { index + 77 };
    Ok(vec![format!("0x{:02X}", decimal_to_bcd(decimal)?)])
}

fn decimal_to_bcd(value: usize) -> Result<u8> {
    if value > 99 {
        bail!("BCD value {value} exceeds two digits");
    }
    Ok(u8::try_from((value / 10) * 16 + value % 10)?)
}

fn parse_scene_message_uses(scene: &[u8], scene_index: usize) -> Result<Vec<MessageUse>> {
    if scene.len() < 0x4C {
        bail!("SC{scene_index:03}.DSC is shorter than its header");
    }
    let end = 0x4Cusize
        .checked_add(usize::from(read_u16(scene, 0x4A)?))
        .context("scene command end overflow")?;
    if end > scene.len() {
        bail!("SC{scene_index:03}.DSC command stream exceeds the resource");
    }
    let mut uses = Vec::new();
    let mut cursor = 0x4Cusize;
    while cursor < end {
        let opcode = *scene
            .get(cursor)
            .with_context(|| format!("SC{scene_index:03} command opcode missing"))?;
        let base_length = *OPCODE_LENGTHS
            .get(usize::from(opcode))
            .with_context(|| format!("SC{scene_index:03} has opcode {opcode:02X}"))?;
        let length = if opcode == 0x14 {
            let first = *scene
                .get(cursor + 4)
                .context("opcode 14 lacks clear child")?;
            let second = *scene.get(cursor + 5).context("opcode 14 lacks set child")?;
            let first_len = *OPCODE_LENGTHS
                .get(usize::from(first))
                .context("opcode 14 clear child is invalid")?;
            let second_len = *OPCODE_LENGTHS
                .get(usize::from(second))
                .context("opcode 14 set child is invalid")?;
            if matches!(first, 0x14) || matches!(second, 0x14) {
                bail!("nested opcode 14 inside opcode 14 is not supported by the observed grammar");
            }
            6 + (first_len - 2) + (second_len - 2)
        } else {
            base_length
        };
        let command_end = cursor
            .checked_add(length)
            .context("scene command length overflow")?;
        if command_end > end {
            bail!("SC{scene_index:03} command at 0x{cursor:X} crosses its string pool");
        }
        let event_key = read_u16(scene, cursor + 1)?;
        if opcode == 0x14 {
            let outer_flag_clear = scene[cursor + 4];
            let outer_flag_set = scene[cursor + 5];
            collect_message_fields(
                scene,
                scene_index,
                cursor,
                event_key,
                outer_flag_clear,
                cursor + 4,
                "outer_clear",
                &mut uses,
            )?;
            let second_base = cursor + 4 + (OPCODE_LENGTHS[usize::from(outer_flag_clear)] - 2);
            collect_message_fields(
                scene,
                scene_index,
                cursor,
                event_key,
                outer_flag_set,
                second_base,
                "outer_set",
                &mut uses,
            )?;
        } else {
            collect_message_fields(
                scene,
                scene_index,
                cursor,
                event_key,
                opcode,
                cursor,
                "",
                &mut uses,
            )?;
        }
        cursor = command_end;
    }
    if cursor != end {
        bail!("SC{scene_index:03} command stream does not end at its string pool");
    }
    Ok(uses)
}

#[allow(clippy::too_many_arguments)]
fn collect_message_fields(
    scene: &[u8],
    scene_index: usize,
    command_offset: usize,
    event_key: u16,
    opcode: u8,
    virtual_base: usize,
    outer_branch: &str,
    uses: &mut Vec<MessageUse>,
) -> Result<()> {
    for field in message_fields(opcode)? {
        let field_offset = virtual_base
            .checked_add(field.offset)
            .context("message field offset overflow")?;
        let code = *scene.get(field_offset).with_context(|| {
            format!("SC{scene_index:03} message field at 0x{field_offset:X} is missing")
        })?;
        if code == 0xFF {
            continue;
        }
        let decimal = bcd_to_decimal(code)?;
        let target = if decimal <= 12 {
            MessageTarget::Common(decimal)
        } else if decimal <= 89 {
            MessageTarget::Scene(decimal - 13)
        } else {
            MessageTarget::Common(decimal - 77)
        };
        let branch = if outer_branch.is_empty() {
            field.branch.to_owned()
        } else if field.branch == "direct" {
            outer_branch.to_owned()
        } else {
            format!("{outer_branch}/{}", field.branch)
        };
        uses.push(MessageUse {
            target,
            reference: TextReference {
                scene_index,
                command_offset,
                event_key,
                opcode,
                opcode_hex: format!("0x{opcode:02X}"),
                field_offset,
                branch,
                slot: field.slot,
                code_hex: format!("0x{code:02X}"),
            },
        });
    }
    Ok(())
}

fn message_fields(opcode: u8) -> Result<Vec<MessageField>> {
    let direct = |offset, slot| MessageField {
        offset,
        branch: "direct",
        slot,
    };
    let clear = |offset, slot| MessageField {
        offset,
        branch: "flag_clear",
        slot,
    };
    let set = |offset, slot| MessageField {
        offset,
        branch: "flag_set",
        slot,
    };
    let fields = match opcode {
        0x00..=0x05 => vec![direct(3, 0)],
        0x06 => vec![clear(4, 0), set(5, 0)],
        0x07..=0x09 => vec![clear(4, 0), clear(5, 1), set(6, 0), set(7, 1)],
        0x0A..=0x0D => vec![direct(4, 0)],
        0x0E..=0x11 => vec![clear(4, 0), clear(5, 1), set(8, 0), set(9, 1)],
        0x12..=0x14 => Vec::new(),
        0x15..=0x18 => vec![
            clear(4, 0),
            clear(5, 1),
            clear(6, 2),
            clear(7, 3),
            set(0x0A, 0),
            set(0x0B, 1),
            set(0x0C, 2),
            set(0x0D, 3),
        ],
        0x19..=0x28 => vec![clear(4, 0), clear(5, 1), set(9, 0), set(0x0A, 1)],
        _ => bail!("unknown scene opcode {opcode:02X}"),
    };
    Ok(fields)
}

fn bcd_to_decimal(value: u8) -> Result<usize> {
    let high = value >> 4;
    let low = value & 0x0F;
    if high > 9 || low > 9 {
        bail!("message code 0x{value:02X} is not packed BCD");
    }
    Ok(usize::from(high) * 10 + usize::from(low))
}

fn parse_string_spans(source: &[u8], start: usize, count: usize) -> Result<Vec<StringSpan>> {
    if start > source.len() {
        bail!("string pool offset 0x{start:X} exceeds source length");
    }
    let mut spans = Vec::with_capacity(count);
    let mut cursor = start;
    for index in 0..count {
        let string_start = cursor;
        let mut euc = Vec::new();
        loop {
            let raw = source.get(cursor..cursor + 2).with_context(|| {
                format!("string {index} at 0x{string_start:X} has no terminator")
            })?;
            cursor += 2;
            if raw == [0, 0] {
                break;
            }
            if !(0x21..=0x7E).contains(&raw[0]) || !(0x21..=0x7E).contains(&raw[1]) {
                bail!(
                    "string {index} at 0x{string_start:X} contains non-JIS word {:02X}{:02X}",
                    raw[1],
                    raw[0]
                );
            }
            euc.push(raw[1] | 0x80);
            euc.push(raw[0] | 0x80);
        }
        let text = EUC_JP
            .decode_without_bom_handling_and_without_replacement(&euc)
            .with_context(|| format!("string {index} at 0x{string_start:X} is invalid JIS"))?
            .into_owned();
        spans.push(StringSpan {
            start: string_start,
            end: cursor,
            text,
        });
    }
    Ok(spans)
}

fn rebuild_common(
    source: &[u8],
    document: &TextDocument,
    plan: &EncodingPlan,
) -> Result<(Vec<u8>, usize)> {
    validate_document_header(document, "common", None, "VNCOM.BIN", source)?;
    if document.entries.len() != COMMON_STRING_COUNT {
        bail!("common.json must contain exactly {COMMON_STRING_COUNT} entries");
    }
    let spans = parse_string_spans(source, COMMON_POOL_OFFSET, COMMON_STRING_COUNT)?;
    validate_entries(document, source, &spans)?;
    let changed = document
        .entries
        .iter()
        .filter(|entry| entry.message != entry.scr_msg)
        .count();
    if changed == 0 {
        return Ok((source.to_vec(), 0));
    }
    let old_end = spans.last().context("common pool has no entries")?.end;
    if source[old_end..].iter().any(|byte| *byte != 0) {
        bail!("VNCOM.BIN has nonzero data after the 23 indexed strings; refusing to move it");
    }
    let mut output = source[..COMMON_POOL_OFFSET].to_vec();
    for entry in &document.entries {
        output.extend_from_slice(&encode_message(&entry.message, plan)?);
    }
    if output.len() > source.len() {
        bail!(
            "translated common strings exceed VNCOM.BIN by {} bytes",
            output.len() - source.len()
        );
    }
    output.resize(source.len(), 0);
    Ok((output, changed))
}

fn rebuild_document(
    source: &[u8],
    document: &TextDocument,
    plan: &EncodingPlan,
) -> Result<(Vec<u8>, usize)> {
    let scene_index = document
        .scene_index
        .context("scenario document lacks index")?;
    validate_document_header(
        document,
        "scenario",
        Some(scene_index),
        &format!("SC{scene_index:03}.DSC"),
        source,
    )?;
    let pool = 0x4Cusize
        .checked_add(usize::from(read_u16(source, 0x4A)?))
        .context("scenario pool offset overflow")?;
    if document.string_pool_offset != pool {
        bail!("SC{scene_index:03}.json string-pool offset was modified");
    }
    let spans = parse_string_spans(source, pool, document.entries.len())?;
    validate_entries(document, source, &spans)?;
    let changed = document
        .entries
        .iter()
        .filter(|entry| entry.message != entry.scr_msg)
        .count();
    if changed == 0 {
        return Ok((source.to_vec(), 0));
    }
    let old_end = spans.last().map_or(pool, |span| span.end);
    let mut output = source[..pool].to_vec();
    for entry in &document.entries {
        output.extend_from_slice(&encode_message(&entry.message, plan)?);
    }
    output.extend_from_slice(&source[old_end..]);
    Ok((output, changed))
}

fn validate_document_header(
    document: &TextDocument,
    kind: &str,
    scene_index: Option<usize>,
    source_file: &str,
    source: &[u8],
) -> Result<()> {
    if document.format != DOCUMENT_FORMAT
        || document.kind != kind
        || document.scene_index != scene_index
        || document.source_file != source_file
        || document.source_sha256 != sha256_hex(source)
    {
        bail!("{source_file}: immutable document metadata does not match the source");
    }
    Ok(())
}

fn validate_entries(document: &TextDocument, source: &[u8], spans: &[StringSpan]) -> Result<()> {
    if document.entries.len() != spans.len() {
        bail!(
            "{}: translation entry count was modified",
            document.source_file
        );
    }
    for (index, (entry, span)) in document.entries.iter().zip(spans).enumerate() {
        if entry.index != index
            || entry.pool_index != index
            || entry.offset != span.start
            || entry.size != span.end - span.start
            || entry.scr_msg != span.text
            || entry.source_bytes_hex != hex_encode(&source[span.start..span.end])
        {
            bail!(
                "{} entry {index}: underscore fields or scr_msg were modified",
                document.source_file
            );
        }
    }
    Ok(())
}

fn encode_message(text: &str, plan: &EncodingPlan) -> Result<Vec<u8>> {
    let normalized = plan.normalize_text(text).map_err(anyhow::Error::msg)?;
    let mut output = Vec::with_capacity(normalized.chars().count() * 2 + 2);
    for character in normalized.chars() {
        let carrier = plan.carrier_for(character).map_err(anyhow::Error::msg)?;
        let cp932 = font::cp932_for_carrier(carrier).map_err(anyhow::Error::msg)?;
        let jis = font::cp932_to_jis(cp932).map_err(anyhow::Error::msg)?;
        output.extend_from_slice(&[jis[1], jis[0]]);
    }
    output.extend_from_slice(&[0, 0]);
    Ok(output)
}

fn protected_vncom_characters(vncom: &[u8]) -> Result<String> {
    let mut protected = BTreeSet::new();
    for raw in vncom[..COMMON_POOL_OFFSET].chunks_exact(2) {
        if !(0x21..=0x7E).contains(&raw[0]) || !(0x21..=0x7E).contains(&raw[1]) {
            continue;
        }
        let euc = [raw[1] | 0x80, raw[0] | 0x80];
        if let Some(text) = EUC_JP.decode_without_bom_handling_and_without_replacement(&euc) {
            protected.extend(text.chars());
        }
    }
    Ok(protected.into_iter().collect())
}

fn read_u16(source: &[u8], offset: usize) -> Result<u16> {
    let raw = source
        .get(offset..offset + 2)
        .with_context(|| format!("u16 at 0x{offset:X} is out of bounds"))?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn write_sector_allocation(
    logical: &mut [u8],
    start_sector: usize,
    sector_count: usize,
    data: &[u8],
) -> Result<()> {
    let start = start_sector
        .checked_mul(SECTOR_SIZE)
        .context("sector start overflow")?;
    let size = sector_count
        .checked_mul(SECTOR_SIZE)
        .context("sector allocation overflow")?;
    if data.len() > size {
        bail!("resource data exceeds its selected sector allocation");
    }
    let allocation = logical
        .get_mut(start..start + size)
        .context("sector allocation exceeds logical disk")?;
    allocation.fill(0);
    allocation[..data.len()].copy_from_slice(data);
    Ok(())
}

fn write_directory_entry(
    system_logical: &mut [u8],
    offset: usize,
    start_sector: usize,
    sector_count: usize,
) -> Result<()> {
    let raw = system_logical
        .get_mut(offset..offset + 8)
        .context("resource directory entry exceeds system disk")?;
    let start = u16::try_from(start_sector).context("resource start sector exceeds u16")?;
    let count = u16::try_from(sector_count).context("resource sector count exceeds u16")?;
    raw[2..4].copy_from_slice(&start.to_le_bytes());
    raw[4..6].copy_from_slice(&count.to_le_bytes());
    Ok(())
}

fn first_trailing_zero_sector(logical: &[u8]) -> usize {
    logical
        .chunks_exact(SECTOR_SIZE)
        .rposition(|sector| sector.iter().any(|byte| *byte != 0))
        .map_or(0, |index| index + 1)
}

fn logical_to_d88(disk: &ParsedDisk, logical: &[u8]) -> Result<Vec<u8>> {
    if logical.len() != disk.logical.len() {
        bail!("logical disk size changed during rebuild");
    }
    let mut output = disk.bytes.clone();
    let mut cursor = 0usize;
    for track in &disk.tracks {
        for range in &track.data_ranges {
            let end = cursor + range.len();
            output[range.clone()].copy_from_slice(&logical[cursor..end]);
            cursor = end;
        }
    }
    if cursor != logical.len() {
        bail!("logical-to-D88 sector accounting mismatch");
    }
    Ok(output)
}

fn match_workspace_sources(pair: &InputPair, manifest: &LocalizationManifest) -> Result<()> {
    if manifest.sources.len() != 2 {
        bail!("localization workspace does not describe exactly two disks");
    }
    for (role, index) in [("A", pair.system_index), ("B", pair.other_index)] {
        let expected = manifest
            .sources
            .iter()
            .find(|source| source.role == role)
            .with_context(|| format!("workspace lacks disk role {role}"))?;
        let actual = &pair.prepared[index];
        let name = actual
            .0
            .file_name()
            .context("D88 input has no filename")?
            .to_string_lossy();
        if expected.source_file != name || expected.source_sha256 != sha256_hex(&actual.2.bytes) {
            bail!("disk {role} does not match the localization workspace source");
        }
    }
    Ok(())
}

fn load_documents(root: &Path, manifest: &LocalizationManifest) -> Result<Vec<TextDocument>> {
    let mut documents = Vec::with_capacity(manifest.documents.len());
    for reference in &manifest.documents {
        let path = root.join(safe_relative_path(&reference.json_file)?);
        let document: TextDocument = read_json(&path)?;
        if document.kind != reference.kind
            || document.scene_index != reference.scene_index
            || document.source_file != reference.source_file
            || document.source_sha256 != reference.source_sha256
            || document.allocation_sha256 != reference.allocation_sha256
            || document.entries.len() != reference.entries
        {
            bail!("{} does not match workspace.json", path.display());
        }
        documents.push(document);
    }
    Ok(documents)
}

fn read_translation_memory(root: &Path) -> Result<HashMap<TranslationKey, String>> {
    let manifest: LocalizationManifest = read_json(&root.join("workspace.json"))?;
    if manifest.format != WORKSPACE_FORMAT {
        bail!("existing output is not a Drrnger localization workspace");
    }
    let mut memory = HashMap::new();
    for reference in &manifest.documents {
        let document: TextDocument =
            read_json(&root.join(safe_relative_path(&reference.json_file)?))?;
        for entry in document.entries {
            let key = TranslationKey {
                kind: document.kind.clone(),
                scene_index: document.scene_index,
                pool_index: entry.pool_index,
                scr_msg: entry.scr_msg,
            };
            if let Some(previous) = memory.insert(key, entry.message.clone()) {
                if previous != entry.message {
                    bail!("existing localization workspace has conflicting translations");
                }
            }
        }
    }
    Ok(memory)
}

fn write_profile(path: &Path) -> Result<()> {
    let profile = serde_json::json!({
        "_format": "drrnger-project-profile-v1",
        "editable_field": "message",
        "immutable_fields": "scr_msg and every underscore-prefixed field",
        "encoding": "little-endian JIS X 0208 carrier codes, 0000-terminated",
        "automatic_wrap": true,
        "normal_fullwidth_columns": 36,
        "hanging_column_37": ["、", "。", "』"],
        "explicit_newline": false,
        "controls": {
            "『": "opens the per-character dialogue sound region",
            "』": "closes the sound region and may hang at column 37"
        },
        "font": {
            "output": "font.tmp beside the rebuilt D88 images",
            "face": font::FONT_FACE,
            "mapping": "deterministic CP932/JIS carrier slots from subs_cn_jp.json"
        },
        "repack": "in-place when a rebuilt scene fits; otherwise append to trailing zero sectors on its original disk and update DIRBLK.BIN"
    });
    write_json(path, &profile)
}

fn validate_managed_output(
    output: &Path,
    overwrite: bool,
    expected_format: &str,
    marker: &str,
) -> Result<()> {
    if !output.exists() {
        return Ok(());
    }
    if !output.is_dir() {
        bail!("output exists and is not a directory: {}", output.display());
    }
    if !overwrite {
        bail!(
            "output already exists: {}; use --overwrite",
            output.display()
        );
    }
    let mut entries = fs::read_dir(output)?;
    if entries.next().is_none() {
        return Ok(());
    }
    let value: serde_json::Value = read_json(&output.join(marker))?;
    if value.get("_format").and_then(|item| item.as_str()) != Some(expected_format) {
        bail!(
            "refusing to overwrite unrecognized directory {}",
            output.display()
        );
    }
    Ok(())
}

fn safe_relative_path(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("workspace contains unsafe relative path {value:?}");
    }
    Ok(path.to_path_buf())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("invalid JSON {}", path.display()))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))
}
