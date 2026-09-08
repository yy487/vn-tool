pub mod font;
mod localize;

pub use localize::{
    extract_localization, pack_localization, LocalizationExtractReport, LocalizationPackReport,
};

use anyhow::{bail, Context, Result};
use encoding_rs::{EUC_JP, SHIFT_JIS};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const WORKSPACE_FORMAT: &str = "drrnger-resource-workspace-v3";
const LEGACY_RESOURCE_WORKSPACE_FORMAT: &str = "drrnger-resource-workspace-v2";
const LEGACY_SECTOR_WORKSPACE_FORMAT: &str = "drrnger-d88-sector-workspace-v1";
const DISK_FORMAT: &str = "drrnger-d88-sector-disk-v2";
const RESOURCE_FORMAT: &str = "drrnger-resource-manifest-v2";
const RESTORED_FILES_FORMAT: &str = "drrnger-restored-original-files-v1";
const D88_HEADER_SIZE: usize = 0x2B0;
const TRACK_TABLE_OFFSET: usize = 0x20;
const TRACK_TABLE_ENTRIES: usize = 164;
const SECTOR_HEADER_SIZE: usize = 16;
const LOGICAL_SECTOR_SIZE: usize = 256;
const GRAPHICS_TABLE_OFFSET: usize = 0x1410;
const SCENARIO_TABLE_OFFSET: usize = 0x1690;
const RESOURCE_ENTRY_SIZE: usize = 8;
const VNCOM_OFFSET: usize = 0x0400;
const VNCOM_SIZE: usize = 0x1000;
const DIRBLK_OFFSET: usize = 0x1410;
const DIRBLK_SIZE: usize = 0x0500;

#[derive(Debug, Clone, Serialize)]
pub struct DiskHeader {
    pub name: Option<String>,
    pub name_raw_hex: String,
    pub write_protected: bool,
    pub media_code: u8,
    pub media_name: String,
    pub declared_size: usize,
    pub header_size: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SectorRecord {
    pub ordinal: usize,
    pub cylinder: u8,
    pub head: u8,
    pub sector_id: u8,
    pub size_code: u8,
    pub sector_count: u16,
    pub density: u8,
    pub deleted: u8,
    pub status: u8,
    pub d88_offset: usize,
    pub data_offset: usize,
    pub data_size: usize,
    pub nominal_size: Option<usize>,
    pub size_matches_code: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrackRecord {
    pub track_slot: usize,
    pub cylinder: u8,
    pub head: u8,
    pub d88_offset: usize,
    pub d88_size: usize,
    pub payload_size: usize,
    pub payload_sha256: String,
    pub sectors: Vec<SectorRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskSummary {
    pub populated_tracks: usize,
    pub sector_count: usize,
    pub logical_payload_size: usize,
    pub uniform_sectors_per_track: Option<usize>,
    pub uniform_sector_size: Option<usize>,
    pub cylinder_min: u8,
    pub cylinder_max: u8,
    pub heads: Vec<u8>,
    pub byte_exact_roundtrip: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskManifest {
    pub format: String,
    pub source_name: String,
    pub source_sha256: String,
    pub original_path: String,
    pub logical_path: String,
    pub header: DiskHeader,
    pub summary: DiskSummary,
    pub tracks: Vec<TrackRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceDisk {
    pub source_name: String,
    pub source_sha256: String,
    pub output_directory: String,
    pub manifest: String,
    pub original: String,
    pub logical: String,
    pub tracks: usize,
    pub sectors: usize,
    pub logical_bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceManifest {
    pub format: String,
    pub tool_version: String,
    pub roles: WorkspaceRoles,
    pub resources_manifest: String,
    pub restored_files_manifest: String,
    pub disks: Vec<WorkspaceDisk>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceRoles {
    pub disk_images: String,
    pub extracted_resources: String,
    pub restored_original_files: String,
}

#[derive(Debug, Clone, Serialize)]
struct RestoredOriginalFile {
    name: String,
    path: String,
    source_disk: String,
    logical_offset: usize,
    byte_length: usize,
    runtime_load_address: String,
    sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct RestoredFilesManifest {
    format: String,
    tool_version: String,
    source_disk: String,
    evidence: String,
    files: Vec<RestoredOriginalFile>,
}

#[derive(Debug, Clone)]
pub struct UnpackReport {
    pub disks: usize,
    pub tracks: usize,
    pub sectors: usize,
    pub logical_bytes: usize,
    pub graphics: usize,
    pub scenarios: usize,
    pub text_records: usize,
    pub restored_original_files: usize,
    pub output: PathBuf,
}

#[derive(Debug, Clone)]
pub struct RestoreOriginalFilesReport {
    pub source_disk: String,
    pub vncom_sha256: String,
    pub dirblk_sha256: String,
    pub output: PathBuf,
}

#[derive(Debug, Clone)]
struct ParsedDisk {
    bytes: Vec<u8>,
    header: DiskHeader,
    tracks: Vec<ParsedTrack>,
    logical: Vec<u8>,
    roundtrip_exact: bool,
}

#[derive(Debug, Clone)]
struct ParsedTrack {
    record: TrackRecord,
    data_ranges: Vec<Range<usize>>,
}

#[derive(Debug, Clone, Serialize)]
struct DirectorySource {
    disk_name: String,
    disk_output_directory: String,
    graphics_table_logical_offset: usize,
    scenario_table_logical_offset: usize,
    entry_layout: String,
}

#[derive(Debug, Clone, Serialize)]
struct GraphicResource {
    index: usize,
    disk_number: u8,
    disk_name: String,
    table_entry_offset: usize,
    start_sector: u16,
    sector_count: u16,
    logical_offset: usize,
    allocation_bytes: usize,
    allocation_sha256: String,
    native_bytes: usize,
    native_sha256: String,
    native_path: String,
    preview_path: String,
    width_bytes: u16,
    pixel_width: usize,
    pixel_height: u16,
    layout_mode: u8,
    compressed_bytes_consumed: usize,
    trailing_padding_bytes: usize,
    header_tail_hex: String,
}

#[derive(Debug, Clone, Serialize)]
struct TextRecord {
    offset: usize,
    byte_length: usize,
    text: String,
}

#[derive(Debug, Clone, Serialize)]
struct ScenarioResource {
    index: usize,
    disk_number: u8,
    disk_name: String,
    table_entry_offset: usize,
    start_sector: u16,
    sector_count: u16,
    logical_offset: usize,
    allocation_bytes: usize,
    allocation_sha256: String,
    native_bytes: usize,
    native_sha256: String,
    native_path: String,
    text_path: String,
    string_pool_offset: usize,
    trailing_padding_bytes: usize,
    text_records: Vec<TextRecord>,
}

#[derive(Debug, Clone, Serialize)]
struct ResourceSummary {
    graphics: usize,
    scenarios: usize,
    utf8_text_records: usize,
}

#[derive(Debug, Clone, Serialize)]
struct ResourceManifest {
    format: String,
    tool_version: String,
    native_naming: String,
    directory_source: DirectorySource,
    summary: ResourceSummary,
    graphics: Vec<GraphicResource>,
    scenarios: Vec<ScenarioResource>,
}

#[derive(Debug, Clone)]
struct ResourceEntry {
    table_offset: usize,
    disk_number: u8,
    start_sector: u16,
    sector_count: u16,
}

#[derive(Debug)]
struct DecodedGraphic {
    width_bytes: usize,
    height: usize,
    mode: u8,
    planes: [Vec<u8>; 3],
    compressed_bytes_consumed: usize,
}

#[derive(Debug)]
struct ResourceCounts {
    graphics: usize,
    scenarios: usize,
    text_records: usize,
}

pub fn unpack(inputs: &[PathBuf], output: &Path, overwrite: bool) -> Result<UnpackReport> {
    if inputs.len() != 2 {
        bail!("Drrnger resource extraction requires exactly two D88 inputs (disk A and disk B)");
    }
    reject_output_containing_inputs(inputs, output)?;

    let mut prepared = Vec::with_capacity(inputs.len());
    let mut directory_names = HashSet::new();
    for input in inputs {
        let bytes = fs::read(input)
            .with_context(|| format!("failed to read D88 image {}", input.display()))?;
        let parsed = parse_d88(bytes)
            .with_context(|| format!("failed to parse D88 image {}", input.display()))?;
        let stem = input
            .file_stem()
            .or_else(|| input.file_name())
            .context("D88 input has no filename")?
            .to_string_lossy();
        let directory = safe_output_segment(&stem);
        if !directory_names.insert(directory.to_ascii_uppercase()) {
            bail!("multiple inputs map to the same output directory {directory:?}");
        }
        prepared.push((input.clone(), directory, parsed));
    }

    validate_drrnger_pair(&prepared)?;
    validate_existing_output(output, overwrite)?;
    let temporary = temporary_sibling(output)?;
    if temporary.exists() {
        fs::remove_dir_all(&temporary)
            .with_context(|| format!("failed to clear temporary output {}", temporary.display()))?;
    }
    fs::create_dir_all(&temporary)
        .with_context(|| format!("failed to create temporary output {}", temporary.display()))?;

    let resource_counts = match write_workspace(&prepared, &temporary) {
        Ok(counts) => counts,
        Err(error) => {
            let _ = fs::remove_dir_all(&temporary);
            return Err(error);
        }
    };
    commit_output(&temporary, output, overwrite)?;

    Ok(UnpackReport {
        disks: prepared.len(),
        tracks: prepared.iter().map(|(_, _, disk)| disk.tracks.len()).sum(),
        sectors: prepared
            .iter()
            .map(|(_, _, disk)| {
                disk.tracks
                    .iter()
                    .map(|track| track.record.sectors.len())
                    .sum::<usize>()
            })
            .sum(),
        logical_bytes: prepared.iter().map(|(_, _, disk)| disk.logical.len()).sum(),
        graphics: resource_counts.graphics,
        scenarios: resource_counts.scenarios,
        text_records: resource_counts.text_records,
        restored_original_files: 2,
        output: output.to_path_buf(),
    })
}

pub fn restore_original_files(input: &Path, output: &Path) -> Result<RestoreOriginalFilesReport> {
    reject_output_containing_inputs(&[input.to_path_buf()], output)?;
    if output.exists() {
        bail!(
            "original-file restore output already exists: {}; choose a new directory",
            output.display()
        );
    }

    let bytes =
        fs::read(input).with_context(|| format!("failed to read D88 image {}", input.display()))?;
    let disk = parse_d88(bytes)
        .with_context(|| format!("failed to parse D88 image {}", input.display()))?;
    if !is_drrnger_system_disk(&disk.logical) {
        bail!(
            "{} is not the Drrnger system disk containing DIRBLK.BIN/VNCOM.BIN",
            input.display()
        );
    }

    let vncom = disk
        .logical
        .get(VNCOM_OFFSET..VNCOM_OFFSET + VNCOM_SIZE)
        .context("VNCOM.BIN range is outside the system disk")?;
    let dirblk = disk
        .logical
        .get(DIRBLK_OFFSET..DIRBLK_OFFSET + DIRBLK_SIZE)
        .context("DIRBLK.BIN range is outside the system disk")?;
    let temporary = temporary_sibling(output)?;
    if temporary.exists() {
        fs::remove_dir_all(&temporary)
            .with_context(|| format!("failed to clear temporary output {}", temporary.display()))?;
    }
    fs::create_dir_all(&temporary)
        .with_context(|| format!("failed to create temporary output {}", temporary.display()))?;
    let write_result = (|| -> Result<()> {
        fs::write(temporary.join("VNCOM.BIN"), vncom).context("failed to restore VNCOM.BIN")?;
        fs::write(temporary.join("DIRBLK.BIN"), dirblk).context("failed to restore DIRBLK.BIN")?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_dir_all(&temporary);
        return Err(error);
    }
    fs::rename(&temporary, output)
        .with_context(|| format!("failed to commit restore output {}", output.display()))?;

    Ok(RestoreOriginalFilesReport {
        source_disk: input
            .file_name()
            .context("D88 input has no filename")?
            .to_string_lossy()
            .into_owned(),
        vncom_sha256: sha256_hex(vncom),
        dirblk_sha256: sha256_hex(dirblk),
        output: output.to_path_buf(),
    })
}

fn parse_d88(bytes: Vec<u8>) -> Result<ParsedDisk> {
    if bytes.len() < D88_HEADER_SIZE {
        bail!("image is shorter than the 0x{D88_HEADER_SIZE:X}-byte D88 header");
    }
    let declared_size =
        usize::try_from(read_u32(&bytes, 0x1C)?).context("D88 declared size does not fit usize")?;
    if declared_size != bytes.len() {
        bail!(
            "declared size {declared_size} does not match actual size {}",
            bytes.len()
        );
    }
    let raw_name = &bytes[..17];
    let raw_name = &raw_name[..raw_name.iter().position(|byte| *byte == 0).unwrap_or(17)];
    let name = (!raw_name.is_empty())
        .then(|| {
            SHIFT_JIS
                .decode_without_bom_handling_and_without_replacement(raw_name)
                .map(|value| value.into_owned())
        })
        .flatten();
    let header = DiskHeader {
        name,
        name_raw_hex: hex_encode(raw_name),
        write_protected: bytes[0x1A] != 0,
        media_code: bytes[0x1B],
        media_name: media_name(bytes[0x1B]).to_owned(),
        declared_size,
        header_size: D88_HEADER_SIZE,
    };

    let mut offsets = Vec::new();
    for slot in 0..TRACK_TABLE_ENTRIES {
        let offset = usize::try_from(read_u32(&bytes, TRACK_TABLE_OFFSET + slot * 4)?)
            .context("D88 track offset does not fit usize")?;
        if offset != 0 {
            if offset < D88_HEADER_SIZE || offset >= bytes.len() {
                bail!("track slot {slot} offset 0x{offset:X} is outside the image");
            }
            if offsets
                .last()
                .is_some_and(|(_, previous)| offset <= *previous)
            {
                bail!("populated track offsets are not strictly increasing at slot {slot}");
            }
            offsets.push((slot, offset));
        }
    }
    if offsets.is_empty() {
        bail!("D88 track table contains no populated tracks");
    }

    let mut tracks = Vec::with_capacity(offsets.len());
    let mut logical = Vec::new();
    for (index, (slot, start)) in offsets.iter().copied().enumerate() {
        let end = offsets
            .get(index + 1)
            .map(|(_, offset)| *offset)
            .unwrap_or(bytes.len());
        let track = parse_track(&bytes, slot, start, end)?;
        for range in &track.data_ranges {
            logical.extend_from_slice(&bytes[range.clone()]);
        }
        tracks.push(track);
    }

    let mut rebuilt = bytes.clone();
    let mut cursor = 0usize;
    for track in &tracks {
        for range in &track.data_ranges {
            let end = cursor + range.len();
            rebuilt[range.clone()].copy_from_slice(&logical[cursor..end]);
            cursor = end;
        }
    }
    if cursor != logical.len() {
        bail!("internal D88 logical-stream accounting mismatch");
    }

    Ok(ParsedDisk {
        roundtrip_exact: rebuilt == bytes,
        bytes,
        header,
        tracks,
        logical,
    })
}

fn parse_track(bytes: &[u8], slot: usize, start: usize, end: usize) -> Result<ParsedTrack> {
    if end <= start || end > bytes.len() || start + SECTOR_HEADER_SIZE > end {
        bail!("invalid D88 byte range for track slot {slot}: 0x{start:X}..0x{end:X}");
    }
    let expected_count = read_u16(bytes, start + 4)?;
    if expected_count == 0 {
        bail!("track slot {slot} declares zero sectors");
    }
    let mut cursor = start;
    let mut sectors = Vec::with_capacity(usize::from(expected_count));
    let mut ranges = Vec::with_capacity(usize::from(expected_count));
    let mut payload = Vec::new();
    for ordinal in 0..usize::from(expected_count) {
        if cursor + SECTOR_HEADER_SIZE > end {
            bail!("track slot {slot} ends inside sector header {ordinal}");
        }
        let count = read_u16(bytes, cursor + 4)?;
        if count != expected_count {
            bail!(
                "track slot {slot} sector {ordinal} declares {count} sectors, expected {expected_count}"
            );
        }
        let data_size = usize::from(read_u16(bytes, cursor + 14)?);
        if data_size == 0 {
            bail!("track slot {slot} sector {ordinal} has zero data bytes");
        }
        let data_start = cursor + SECTOR_HEADER_SIZE;
        let data_end = data_start
            .checked_add(data_size)
            .context("D88 sector end offset overflow")?;
        if data_end > end {
            bail!("track slot {slot} sector {ordinal} crosses its track boundary");
        }
        let nominal_size = 128usize.checked_shl(u32::from(bytes[cursor + 3]));
        sectors.push(SectorRecord {
            ordinal,
            cylinder: bytes[cursor],
            head: bytes[cursor + 1],
            sector_id: bytes[cursor + 2],
            size_code: bytes[cursor + 3],
            sector_count: count,
            density: bytes[cursor + 6],
            deleted: bytes[cursor + 7],
            status: bytes[cursor + 8],
            d88_offset: cursor,
            data_offset: data_start,
            data_size,
            nominal_size,
            size_matches_code: nominal_size == Some(data_size),
        });
        ranges.push(data_start..data_end);
        payload.extend_from_slice(&bytes[data_start..data_end]);
        cursor = data_end;
    }
    if cursor != end {
        bail!(
            "track slot {slot} has {} unparsed trailing byte(s)",
            end - cursor
        );
    }
    let first = sectors.first().context("parsed D88 track has no sectors")?;
    if sectors
        .iter()
        .any(|sector| sector.cylinder != first.cylinder || sector.head != first.head)
    {
        bail!("track slot {slot} mixes multiple cylinder/head values");
    }
    let record = TrackRecord {
        track_slot: slot,
        cylinder: first.cylinder,
        head: first.head,
        d88_offset: start,
        d88_size: end - start,
        payload_size: payload.len(),
        payload_sha256: sha256_hex(&payload),
        sectors,
    };
    Ok(ParsedTrack {
        record,
        data_ranges: ranges,
    })
}

fn validate_drrnger_pair(prepared: &[(PathBuf, String, ParsedDisk)]) -> Result<()> {
    let system_indices = prepared
        .iter()
        .enumerate()
        .filter(|(_, (_, _, disk))| is_drrnger_system_disk(&disk.logical))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if system_indices.len() != 1 {
        bail!(
            "expected exactly one Drrnger system disk with DIRBLK.BIN/VNCOM.BIN signatures, found {}",
            system_indices.len()
        );
    }
    let system = &prepared[system_indices[0]].2.logical;
    let graphics = parse_resource_table(system, GRAPHICS_TABLE_OFFSET)?;
    let scenarios = parse_resource_table(system, SCENARIO_TABLE_OFFSET)?;
    if graphics.len() != 63 || scenarios.len() != 57 {
        bail!(
            "unexpected Drrnger directory sizes: graphics={}, scenarios={} (expected 63/57)",
            graphics.len(),
            scenarios.len()
        );
    }
    let other_index = 1 - system_indices[0];
    let disks = [&prepared[system_indices[0]].2, &prepared[other_index].2];
    for entry in graphics.iter().chain(&scenarios) {
        validate_resource_range(entry, &disks)?;
    }
    for entry in &graphics {
        let blob = resource_slice(entry, &disks)?;
        decode_graphic(blob).with_context(|| {
            format!(
                "invalid graphic directory entry at 0x{:X}",
                entry.table_offset
            )
        })?;
    }
    Ok(())
}

fn is_drrnger_system_disk(logical: &[u8]) -> bool {
    logical.first() == Some(&0xFA)
        && logical
            .get(0x1B10..0x1B1A)
            .is_some_and(|value| value == b"DIRBLK.BIN")
        && logical
            .get(0x1B1C..0x1B25)
            .is_some_and(|value| value == b"VNCOM.BIN")
}

fn parse_resource_table(logical: &[u8], offset: usize) -> Result<Vec<ResourceEntry>> {
    let mut entries = Vec::new();
    for index in 0..256usize {
        let entry_offset = offset + index * RESOURCE_ENTRY_SIZE;
        let raw = logical
            .get(entry_offset..entry_offset + RESOURCE_ENTRY_SIZE)
            .with_context(|| format!("resource table at 0x{offset:X} has no terminator"))?;
        if raw.iter().all(|byte| *byte == 0) {
            return Ok(entries);
        }
        if !matches!(raw[0], 1 | 2) || raw[1] != 0 || raw[6] != 0 || raw[7] != 0 {
            bail!("malformed resource entry at logical offset 0x{entry_offset:X}");
        }
        let sector_count = u16::from_le_bytes([raw[4], raw[5]]);
        if sector_count == 0 {
            bail!("zero-length resource entry at logical offset 0x{entry_offset:X}");
        }
        entries.push(ResourceEntry {
            table_offset: entry_offset,
            disk_number: raw[0],
            start_sector: u16::from_le_bytes([raw[2], raw[3]]),
            sector_count,
        });
    }
    bail!("resource table at 0x{offset:X} exceeds 256 entries")
}

fn validate_resource_range(entry: &ResourceEntry, disks: &[&ParsedDisk; 2]) -> Result<()> {
    let disk = disks
        .get(usize::from(entry.disk_number - 1))
        .context("resource entry disk number is outside the supplied disk pair")?;
    let start = usize::from(entry.start_sector) * LOGICAL_SECTOR_SIZE;
    let size = usize::from(entry.sector_count) * LOGICAL_SECTOR_SIZE;
    let end = start.checked_add(size).context("resource range overflow")?;
    if end > disk.logical.len() {
        bail!(
            "resource at table offset 0x{:X} exceeds disk {}: 0x{start:X}..0x{end:X}",
            entry.table_offset,
            entry.disk_number
        );
    }
    Ok(())
}

fn resource_slice<'a>(entry: &ResourceEntry, disks: &[&'a ParsedDisk; 2]) -> Result<&'a [u8]> {
    validate_resource_range(entry, disks)?;
    let disk = disks[usize::from(entry.disk_number - 1)];
    let start = usize::from(entry.start_sector) * LOGICAL_SECTOR_SIZE;
    let size = usize::from(entry.sector_count) * LOGICAL_SECTOR_SIZE;
    Ok(&disk.logical[start..start + size])
}

fn write_workspace(
    prepared: &[(PathBuf, String, ParsedDisk)],
    root: &Path,
) -> Result<ResourceCounts> {
    let mut disks = Vec::with_capacity(prepared.len());
    for (source, directory, disk) in prepared {
        let disk_root = root.join(directory);
        fs::create_dir_all(&disk_root)
            .with_context(|| format!("failed to create {}", disk_root.display()))?;
        fs::write(disk_root.join("original.d88"), &disk.bytes)
            .with_context(|| format!("failed to write original copy for {}", source.display()))?;
        fs::write(disk_root.join("logical.bin"), &disk.logical)
            .with_context(|| format!("failed to write logical image for {}", source.display()))?;

        let sector_count = disk
            .tracks
            .iter()
            .map(|track| track.record.sectors.len())
            .sum::<usize>();
        let uniform_sectors_per_track =
            uniform_value(disk.tracks.iter().map(|track| track.record.sectors.len()));
        let uniform_sector_size = uniform_value(
            disk.tracks
                .iter()
                .flat_map(|track| track.record.sectors.iter().map(|sector| sector.data_size)),
        );
        let mut heads = disk
            .tracks
            .iter()
            .map(|track| track.record.head)
            .collect::<Vec<_>>();
        heads.sort_unstable();
        heads.dedup();
        let cylinder_min = disk
            .tracks
            .iter()
            .map(|track| track.record.cylinder)
            .min()
            .context("D88 contains no cylinder")?;
        let cylinder_max = disk
            .tracks
            .iter()
            .map(|track| track.record.cylinder)
            .max()
            .context("D88 contains no cylinder")?;
        let source_name = source
            .file_name()
            .context("D88 input has no filename")?
            .to_string_lossy()
            .into_owned();
        let source_sha256 = sha256_hex(&disk.bytes);
        let manifest = DiskManifest {
            format: DISK_FORMAT.to_owned(),
            source_name: source_name.clone(),
            source_sha256: source_sha256.clone(),
            original_path: "original.d88".to_owned(),
            logical_path: "logical.bin".to_owned(),
            header: disk.header.clone(),
            summary: DiskSummary {
                populated_tracks: disk.tracks.len(),
                sector_count,
                logical_payload_size: disk.logical.len(),
                uniform_sectors_per_track,
                uniform_sector_size,
                cylinder_min,
                cylinder_max,
                heads,
                byte_exact_roundtrip: disk.roundtrip_exact,
            },
            tracks: disk
                .tracks
                .iter()
                .map(|track| track.record.clone())
                .collect(),
        };
        write_json(&disk_root.join("manifest.json"), &manifest)?;
        disks.push(WorkspaceDisk {
            source_name,
            source_sha256,
            output_directory: directory.clone(),
            manifest: format!("{directory}/manifest.json"),
            original: format!("{directory}/original.d88"),
            logical: format!("{directory}/logical.bin"),
            tracks: disk.tracks.len(),
            sectors: sector_count,
            logical_bytes: disk.logical.len(),
        });
    }

    write_restored_original_files(prepared, root)?;
    let resource_counts = write_resources(prepared, root)?;
    write_json(
        &root.join("workspace.json"),
        &WorkspaceManifest {
            format: WORKSPACE_FORMAT.to_owned(),
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            roles: WorkspaceRoles {
                disk_images: ".".to_owned(),
                extracted_resources: "resources".to_owned(),
                restored_original_files: "original_files".to_owned(),
            },
            resources_manifest: "resources/manifest.json".to_owned(),
            restored_files_manifest: "original_files/manifest.json".to_owned(),
            disks,
        },
    )?;
    Ok(resource_counts)
}

fn write_restored_original_files(
    prepared: &[(PathBuf, String, ParsedDisk)],
    root: &Path,
) -> Result<()> {
    let system_index = prepared
        .iter()
        .position(|(_, _, disk)| is_drrnger_system_disk(&disk.logical))
        .context("Drrnger system disk was not found")?;
    let (source, _, disk) = &prepared[system_index];
    let source_disk = source
        .file_name()
        .context("D88 input has no filename")?
        .to_string_lossy()
        .into_owned();
    let output = root.join("original_files");
    fs::create_dir_all(&output)
        .with_context(|| format!("failed to create {}", output.display()))?;

    let specs = [
        ("VNCOM.BIN", VNCOM_OFFSET, VNCOM_SIZE, "DS:2000"),
        ("DIRBLK.BIN", DIRBLK_OFFSET, DIRBLK_SIZE, "DS:3010"),
    ];
    let mut files = Vec::with_capacity(specs.len());
    for (name, logical_offset, byte_length, runtime_load_address) in specs {
        let bytes = disk
            .logical
            .get(logical_offset..logical_offset + byte_length)
            .with_context(|| format!("restored file {name} is outside the system disk"))?;
        fs::write(output.join(name), bytes).with_context(|| format!("failed to restore {name}"))?;
        files.push(RestoredOriginalFile {
            name: name.to_owned(),
            path: name.to_owned(),
            source_disk: source_disk.clone(),
            logical_offset,
            byte_length,
            runtime_load_address: runtime_load_address.to_owned(),
            sha256: sha256_hex(bytes),
        });
    }

    write_json(
        &output.join("manifest.json"),
        &RestoredFilesManifest {
            format: RESTORED_FILES_FORMAT.to_owned(),
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            source_disk,
            evidence: "runtime 0x68E6 opens DIRBLK.BIN and VNCOM.BIN with DOS int 21h, then reads exactly 0x0500 bytes to DS:3010 and 0x1000 bytes to DS:2000".to_owned(),
            files,
        },
    )
}

fn write_resources(
    prepared: &[(PathBuf, String, ParsedDisk)],
    root: &Path,
) -> Result<ResourceCounts> {
    let system_index = prepared
        .iter()
        .position(|(_, _, disk)| is_drrnger_system_disk(&disk.logical))
        .context("Drrnger system disk was not found")?;
    let other_index = 1 - system_index;
    let disk_indices = [system_index, other_index];
    let disk_refs = [&prepared[system_index].2, &prepared[other_index].2];
    let system = &prepared[system_index].2.logical;
    let graphics_entries = parse_resource_table(system, GRAPHICS_TABLE_OFFSET)?;
    let scenario_entries = parse_resource_table(system, SCENARIO_TABLE_OFFSET)?;

    let resources_root = root.join("resources");
    let native_root = resources_root.join("native");
    let preview_root = resources_root.join("preview");
    let text_root = resources_root.join("text");
    fs::create_dir_all(&native_root)?;
    fs::create_dir_all(&preview_root)?;
    fs::create_dir_all(&text_root)?;

    let mut graphics = Vec::with_capacity(graphics_entries.len());
    for (index, entry) in graphics_entries.iter().enumerate() {
        let blob = resource_slice(entry, &disk_refs)?;
        let decoded = decode_graphic(blob)
            .with_context(|| format!("failed to decode graphic resource {index:03}"))?;
        let basename = format!("CG{index:03}");
        let native_path = format!("native/{basename}.DGI");
        let preview_path = format!("preview/{basename}.bmp");
        let native_size = 16usize
            .checked_add(decoded.compressed_bytes_consumed)
            .context("graphic native size overflow")?;
        let native = blob
            .get(..native_size)
            .context("decoded graphic exceeds its directory allocation")?;
        fs::write(resources_root.join(&native_path), native)?;
        fs::write(
            resources_root.join(&preview_path),
            render_planar_bmp(&decoded)?,
        )?;
        let disk_index = disk_indices[usize::from(entry.disk_number - 1)];
        let disk_name = prepared[disk_index]
            .0
            .file_name()
            .context("D88 input has no filename")?
            .to_string_lossy()
            .into_owned();
        let trailing_padding_bytes = blob
            .len()
            .checked_sub(16 + decoded.compressed_bytes_consumed)
            .context("decoded graphic exceeds its directory allocation")?;
        graphics.push(GraphicResource {
            index,
            disk_number: entry.disk_number,
            disk_name,
            table_entry_offset: entry.table_offset,
            start_sector: entry.start_sector,
            sector_count: entry.sector_count,
            logical_offset: usize::from(entry.start_sector) * LOGICAL_SECTOR_SIZE,
            allocation_bytes: blob.len(),
            allocation_sha256: sha256_hex(blob),
            native_bytes: native.len(),
            native_sha256: sha256_hex(native),
            native_path,
            preview_path,
            width_bytes: u16::try_from(decoded.width_bytes).context("graphic width overflow")?,
            pixel_width: decoded.width_bytes * 8,
            pixel_height: u16::try_from(decoded.height).context("graphic height overflow")?,
            layout_mode: decoded.mode,
            compressed_bytes_consumed: decoded.compressed_bytes_consumed,
            trailing_padding_bytes,
            header_tail_hex: hex_encode(&blob[5..16]),
        });
    }

    let mut scenarios = Vec::with_capacity(scenario_entries.len());
    let mut text_record_count = 0usize;
    for (index, entry) in scenario_entries.iter().enumerate() {
        let blob = resource_slice(entry, &disk_refs)?;
        if blob.len() < 0x4C {
            bail!("scenario resource {index:03} is shorter than its 0x4C-byte header");
        }
        let string_pool_offset = 0x4Cusize
            .checked_add(usize::from(read_u16(blob, 0x4A)?))
            .context("scenario string-pool offset overflow")?;
        if string_pool_offset > blob.len() {
            bail!(
                "scenario resource {index:03} string-pool offset 0x{string_pool_offset:X} exceeds its allocation"
            );
        }
        let native_size = scenario_native_size(blob);
        let native = &blob[..native_size];
        let text_records = extract_jis_text(native, string_pool_offset);
        text_record_count += text_records.len();
        let basename = format!("SC{index:03}");
        let native_path = format!("native/{basename}.DSC");
        let text_path = format!("text/{basename}.txt");
        fs::write(resources_root.join(&native_path), native)?;
        let disk_index = disk_indices[usize::from(entry.disk_number - 1)];
        let disk_name = prepared[disk_index]
            .0
            .file_name()
            .context("D88 input has no filename")?
            .to_string_lossy()
            .into_owned();
        let mut text = format!(
            "# scene {index:03}\n# source={disk_name} sector=0x{:04X} count=0x{:04X} string_pool_offset=0x{string_pool_offset:04X}\n",
            entry.start_sector, entry.sector_count
        );
        for record in &text_records {
            text.push_str(&format!("[0x{:04X}] {}\n", record.offset, record.text));
        }
        fs::write(resources_root.join(&text_path), text.as_bytes())?;
        scenarios.push(ScenarioResource {
            index,
            disk_number: entry.disk_number,
            disk_name,
            table_entry_offset: entry.table_offset,
            start_sector: entry.start_sector,
            sector_count: entry.sector_count,
            logical_offset: usize::from(entry.start_sector) * LOGICAL_SECTOR_SIZE,
            allocation_bytes: blob.len(),
            allocation_sha256: sha256_hex(blob),
            native_bytes: native.len(),
            native_sha256: sha256_hex(native),
            native_path,
            text_path,
            string_pool_offset,
            trailing_padding_bytes: blob.len() - native.len(),
            text_records,
        });
    }

    let system_source_name = prepared[system_index]
        .0
        .file_name()
        .context("D88 input has no filename")?
        .to_string_lossy()
        .into_owned();
    let manifest = ResourceManifest {
        format: RESOURCE_FORMAT.to_owned(),
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        native_naming: "CGnnn.DGI and SCnnn.DSC are deterministic semantic names generated from runtime directory indices; the published block directory contains no per-entry filenames, and DGI/DSC are tool-defined extensions".to_owned(),
        directory_source: DirectorySource {
            disk_name: system_source_name,
            disk_output_directory: prepared[system_index].1.clone(),
            graphics_table_logical_offset: GRAPHICS_TABLE_OFFSET,
            scenario_table_logical_offset: SCENARIO_TABLE_OFFSET,
            entry_layout: "u8 disk_number (1=A,2=B), u8 reserved, u16le start_sector, u16le sector_count, u16le reserved; sector_size=256".to_owned(),
        },
        summary: ResourceSummary {
            graphics: graphics.len(),
            scenarios: scenarios.len(),
            utf8_text_records: text_record_count,
        },
        graphics,
        scenarios,
    };
    write_json(&resources_root.join("manifest.json"), &manifest)?;
    Ok(ResourceCounts {
        graphics: manifest.summary.graphics,
        scenarios: manifest.summary.scenarios,
        text_records: manifest.summary.utf8_text_records,
    })
}

fn scenario_native_size(blob: &[u8]) -> usize {
    let minimum = blob.len().min(0x4C);
    let Some(last_nonzero) = blob.iter().rposition(|byte| *byte != 0) else {
        return minimum;
    };
    // Scenario text is terminated by a zero word. Keep that terminator while
    // removing only the remaining sector-alignment zero fill.
    blob.len()
        .min(minimum.max(last_nonzero + 1).saturating_add(2))
}

fn decode_graphic(blob: &[u8]) -> Result<DecodedGraphic> {
    if blob.len() < 16 {
        bail!("graphic allocation is shorter than its 16-byte header");
    }
    let width_bytes = usize::from(read_u16(blob, 0)?);
    let height = usize::from(read_u16(blob, 2)?);
    let mode = blob[4];
    if width_bytes == 0 || height == 0 {
        bail!("graphic has zero width or height");
    }
    if mode > 3 {
        bail!("unsupported graphic layout mode {mode}");
    }
    let plane_size = width_bytes
        .checked_mul(height)
        .context("graphic plane size overflow")?;
    let source = &blob[16..];
    let mut cursor = 0usize;
    let mut decoded_planes = Vec::with_capacity(3);
    for _ in 0..3 {
        let streamed = if mode == 0 {
            let end = cursor
                .checked_add(plane_size)
                .context("raw graphic size overflow")?;
            let plane = source
                .get(cursor..end)
                .context("raw graphic ends before all three planes")?
                .to_vec();
            cursor = end;
            plane
        } else {
            decode_rle_plane(source, &mut cursor, plane_size)?
        };
        decoded_planes.push(arrange_plane(&streamed, width_bytes, height, mode));
    }
    let planes: [Vec<u8>; 3] = decoded_planes
        .try_into()
        .map_err(|_| anyhow::anyhow!("internal graphic plane count mismatch"))?;
    Ok(DecodedGraphic {
        width_bytes,
        height,
        mode,
        planes,
        compressed_bytes_consumed: cursor,
    })
}

fn decode_rle_plane(source: &[u8], cursor: &mut usize, expected: usize) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(expected);
    while output.len() < expected {
        let value = *source
            .get(*cursor)
            .context("RLE stream ends before the plane is complete")?;
        *cursor += 1;
        output.push(value);
        if output.len() == expected {
            break;
        }
        if source.get(*cursor) == Some(&value) {
            *cursor += 1;
            let count = *source
                .get(*cursor)
                .context("RLE marker has no repeat count")?;
            *cursor += 1;
            // The original 8086 decoder decrements an 8-bit CL before a
            // do/while loop. Consequently 0 encodes a 256-byte run and 1
            // encodes a 257-byte run; values 2..255 encode themselves.
            let additional = match count {
                0 => 255,
                1 => 256,
                value => usize::from(value - 1),
            };
            if output.len() + additional > expected {
                bail!("RLE run crosses a plane boundary");
            }
            output.extend(std::iter::repeat_n(value, additional));
        }
    }
    Ok(output)
}

fn arrange_plane(streamed: &[u8], width: usize, height: usize, mode: u8) -> Vec<u8> {
    if matches!(mode, 0 | 1) {
        return streamed.to_vec();
    }
    let mut output = vec![0u8; streamed.len()];
    let mut source = 0usize;
    if mode == 2 {
        for x in 0..width {
            for y in 0..height {
                output[y * width + x] = streamed[source];
                source += 1;
            }
        }
    } else {
        for x in 0..width {
            for y in (0..height).step_by(2) {
                output[y * width + x] = streamed[source];
                source += 1;
            }
            for y in (1..height).step_by(2) {
                output[y * width + x] = streamed[source];
                source += 1;
            }
        }
    }
    output
}

fn render_planar_bmp(graphic: &DecodedGraphic) -> Result<Vec<u8>> {
    let width = graphic
        .width_bytes
        .checked_mul(8)
        .context("BMP width overflow")?;
    let row_bytes = width.checked_mul(3).context("BMP row size overflow")?;
    let stride = row_bytes.checked_add(3).context("BMP stride overflow")? & !3;
    let pixel_bytes = stride
        .checked_mul(graphic.height)
        .context("BMP pixel size overflow")?;
    let file_size = 54usize
        .checked_add(pixel_bytes)
        .context("BMP file size overflow")?;
    let mut bmp = Vec::with_capacity(file_size);
    bmp.extend_from_slice(b"BM");
    bmp.extend_from_slice(&u32::try_from(file_size)?.to_le_bytes());
    bmp.extend_from_slice(&[0u8; 4]);
    bmp.extend_from_slice(&54u32.to_le_bytes());
    bmp.extend_from_slice(&40u32.to_le_bytes());
    bmp.extend_from_slice(&i32::try_from(width)?.to_le_bytes());
    bmp.extend_from_slice(&i32::try_from(graphic.height)?.to_le_bytes());
    bmp.extend_from_slice(&1u16.to_le_bytes());
    bmp.extend_from_slice(&24u16.to_le_bytes());
    bmp.extend_from_slice(&0u32.to_le_bytes());
    bmp.extend_from_slice(&u32::try_from(pixel_bytes)?.to_le_bytes());
    bmp.extend_from_slice(&2835i32.to_le_bytes());
    bmp.extend_from_slice(&2835i32.to_le_bytes());
    bmp.extend_from_slice(&0u32.to_le_bytes());
    bmp.extend_from_slice(&0u32.to_le_bytes());
    let padding = stride - row_bytes;
    for y in (0..graphic.height).rev() {
        for x in 0..width {
            let byte_index = y * graphic.width_bytes + x / 8;
            let mask = 0x80u8 >> (x & 7);
            let blue = if graphic.planes[0][byte_index] & mask != 0 {
                255
            } else {
                0
            };
            let red = if graphic.planes[1][byte_index] & mask != 0 {
                255
            } else {
                0
            };
            let green = if graphic.planes[2][byte_index] & mask != 0 {
                255
            } else {
                0
            };
            bmp.extend_from_slice(&[blue, green, red]);
        }
        bmp.extend(std::iter::repeat_n(0, padding));
    }
    Ok(bmp)
}

fn extract_jis_text(blob: &[u8], start: usize) -> Vec<TextRecord> {
    let mut records = Vec::new();
    let mut cursor = start;
    while cursor + 1 < blob.len() {
        if !is_jis_pair(blob[cursor], blob[cursor + 1]) {
            cursor += 1;
            continue;
        }
        let run_start = cursor;
        let mut euc_jp = Vec::new();
        while cursor + 1 < blob.len() && is_jis_pair(blob[cursor], blob[cursor + 1]) {
            // The script stores each JIS X 0208 code as a little-endian word,
            // so the row/cell bytes must be swapped before EUC-JP decoding.
            euc_jp.push(blob[cursor + 1] | 0x80);
            euc_jp.push(blob[cursor] | 0x80);
            cursor += 2;
        }
        if euc_jp.len() < 4 {
            continue;
        }
        let Some(decoded) = EUC_JP.decode_without_bom_handling_and_without_replacement(&euc_jp)
        else {
            continue;
        };
        let decoded = decoded.into_owned();
        if decoded.chars().any(is_japanese_character) {
            records.push(TextRecord {
                offset: run_start,
                byte_length: euc_jp.len(),
                text: decoded,
            });
        }
    }
    records
}

fn is_jis_pair(first: u8, second: u8) -> bool {
    (0x21..=0x7E).contains(&first) && (0x21..=0x7E).contains(&second)
}

fn is_japanese_character(character: char) -> bool {
    matches!(
        character,
        '\u{3000}'..='\u{30FF}' | '\u{3400}'..='\u{9FFF}' | '\u{FF01}'..='\u{FFEF}'
    )
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value).context("failed to serialize JSON")?;
    bytes.push(b'\n');
    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))
}

fn uniform_value(values: impl IntoIterator<Item = usize>) -> Option<usize> {
    let mut values = values.into_iter();
    let first = values.next()?;
    values.all(|value| value == first).then_some(first)
}

fn validate_existing_output(output: &Path, overwrite: bool) -> Result<()> {
    if !output.exists() {
        return Ok(());
    }
    if !overwrite {
        bail!(
            "output already exists: {}; use --overwrite to replace a recognized workspace",
            output.display()
        );
    }
    if !output.is_dir() {
        bail!("overwrite target is not a directory: {}", output.display());
    }
    let manifest_path = output.join("workspace.json");
    let bytes = fs::read(&manifest_path).with_context(|| {
        format!(
            "refusing to overwrite unrecognized directory {}; workspace.json is missing",
            output.display()
        )
    })?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid existing manifest {}", manifest_path.display()))?;
    let format = value.get("format").and_then(|value| value.as_str());
    if !matches!(
        format,
        Some(WORKSPACE_FORMAT | LEGACY_RESOURCE_WORKSPACE_FORMAT | LEGACY_SECTOR_WORKSPACE_FORMAT)
    ) {
        bail!(
            "refusing to overwrite an unrecognized workspace: {}",
            output.display()
        );
    }
    Ok(())
}

fn commit_output(temporary: &Path, output: &Path, overwrite: bool) -> Result<()> {
    if !output.exists() {
        return fs::rename(temporary, output)
            .with_context(|| format!("failed to commit output {}", output.display()));
    }
    if !overwrite {
        bail!("output appeared while unpacking: {}", output.display());
    }
    let backup = backup_sibling(output)?;
    fs::rename(output, &backup)
        .with_context(|| format!("failed to stage existing output {}", output.display()))?;
    if let Err(error) = fs::rename(temporary, output) {
        let _ = fs::rename(&backup, output);
        return Err(error).with_context(|| format!("failed to commit output {}", output.display()));
    }
    fs::remove_dir_all(&backup).with_context(|| {
        format!(
            "failed to remove replaced workspace backup {}",
            backup.display()
        )
    })
}

fn reject_output_containing_inputs(inputs: &[PathBuf], output: &Path) -> Result<()> {
    let output_absolute = absolute_for_compare(output)?;
    for input in inputs {
        let input_absolute = input
            .canonicalize()
            .with_context(|| format!("failed to resolve input {}", input.display()))?;
        if input_absolute.starts_with(&output_absolute) {
            bail!(
                "output directory must not contain source input {}",
                input.display()
            );
        }
    }
    Ok(())
}

fn absolute_for_compare(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return path
            .canonicalize()
            .with_context(|| format!("failed to resolve {}", path.display()));
    }
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = parent
        .canonicalize()
        .with_context(|| format!("failed to resolve output parent {}", parent.display()))?;
    let name = path
        .file_name()
        .context("output path has no final component")?;
    Ok(parent.join(name))
}

fn temporary_sibling(output: &Path) -> Result<PathBuf> {
    sibling_with_tag(output, "tmp")
}

fn backup_sibling(output: &Path) -> Result<PathBuf> {
    sibling_with_tag(output, "backup")
}

fn sibling_with_tag(output: &Path, tag: &str) -> Result<PathBuf> {
    let parent = output
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = output
        .file_name()
        .context("output path has no final component")?
        .to_string_lossy();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock predates UNIX epoch")?
        .as_nanos();
    Ok(parent.join(format!(".{name}.{tag}-{}-{stamp}", std::process::id())))
}

fn safe_output_segment(value: &str) -> String {
    let mut output = value
        .chars()
        .map(|character| {
            if character.is_control()
                || matches!(
                    character,
                    '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
                )
            {
                '_'
            } else {
                character
            }
        })
        .collect::<String>();
    while output.ends_with([' ', '.']) {
        output.pop();
    }
    if output.is_empty() {
        output.push_str("disk");
    }
    let upper = output.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    ) {
        output.insert(0, '_');
    }
    output
}

fn media_name(code: u8) -> &'static str {
    match code {
        0x00 => "2D",
        0x10 => "2DD",
        0x20 => "2HD",
        _ => "unknown",
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let raw = bytes
        .get(offset..offset + 2)
        .with_context(|| format!("u16 read at 0x{offset:X} is out of bounds"))?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw = bytes
        .get(offset..offset + 4)
        .with_context(|| format!("u32 read at 0x{offset:X} is out of bounds"))?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let track_size = 2 * (SECTOR_HEADER_SIZE + 256);
        let mut bytes = vec![0u8; D88_HEADER_SIZE + track_size];
        let size = u32::try_from(bytes.len()).unwrap();
        bytes[0x1B] = 0x10;
        bytes[0x1C..0x20].copy_from_slice(&size.to_le_bytes());
        bytes[TRACK_TABLE_OFFSET..TRACK_TABLE_OFFSET + 4]
            .copy_from_slice(&(D88_HEADER_SIZE as u32).to_le_bytes());
        let mut cursor = D88_HEADER_SIZE;
        for sector in 0..2u8 {
            bytes[cursor] = 0;
            bytes[cursor + 1] = 0;
            bytes[cursor + 2] = sector + 1;
            bytes[cursor + 3] = 1;
            bytes[cursor + 4..cursor + 6].copy_from_slice(&2u16.to_le_bytes());
            bytes[cursor + 14..cursor + 16].copy_from_slice(&256u16.to_le_bytes());
            bytes[cursor + 16..cursor + 16 + 256].fill(sector + 1);
            cursor += SECTOR_HEADER_SIZE + 256;
        }
        bytes
    }

    #[test]
    fn parses_and_roundtrips_sector_payloads() {
        let parsed = parse_d88(fixture()).unwrap();
        assert_eq!(parsed.tracks.len(), 1);
        assert_eq!(parsed.tracks[0].record.sectors.len(), 2);
        assert_eq!(parsed.logical.len(), 512);
        assert!(parsed.roundtrip_exact);
    }

    #[test]
    fn rejects_declared_size_mismatch() {
        let mut bytes = fixture();
        bytes.push(0);
        assert!(parse_d88(bytes)
            .unwrap_err()
            .to_string()
            .contains("declared size"));
    }

    #[test]
    fn expands_equal_byte_rle_marker() {
        let source = [0x12, 0x12, 4, 0x34];
        let mut cursor = 0;
        let decoded = decode_rle_plane(&source, &mut cursor, 5).unwrap();
        assert_eq!(decoded, [0x12, 0x12, 0x12, 0x12, 0x34]);
        assert_eq!(cursor, source.len());
    }

    #[test]
    fn converts_mode_three_stream_order_to_rows() {
        let streamed = [0, 2, 1, 3, 4, 6, 5, 7];
        assert_eq!(arrange_plane(&streamed, 2, 4, 3), [0, 4, 1, 5, 2, 6, 3, 7]);
    }
}
