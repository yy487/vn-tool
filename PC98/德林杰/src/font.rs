use encoding_rs::SHIFT_JIS;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

const EMBEDDED_FONT: &[u8] = include_bytes!("../assets/font.tmp");
const EMBEDDED_SUBSTITUTIONS: &str = include_str!("../assets/subs_cn_jp.json");
const BMP_FILE_SIZE: usize = 0x8003E;
const BMP_PIXEL_OFFSET: usize = 0x3E;
const BMP_WIDTH: usize = 2048;
const BMP_HEIGHT: usize = 2048;
const BMP_STRIDE: usize = 256;
const GLYPH_WIDTH: usize = 16;
const GLYPH_HEIGHT: usize = 16;
const GLYPH_BYTES_PER_ROW: usize = 2;
const GLYPH_BYTES: usize = GLYPH_HEIGHT * GLYPH_BYTES_PER_ROW;
pub const FONT_FACE: &str = "新宋体";

type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Debug)]
pub struct SubstitutionMap {
    mappings: HashMap<char, char>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FontPatchRequest {
    pub carrier: char,
    pub replacement: char,
}

#[derive(Clone, Debug)]
pub struct FontBuild {
    pub bytes: Vec<u8>,
    pub patched_glyphs: usize,
}

#[derive(Clone, Debug)]
pub struct EncodingPlan {
    display_to_carrier: BTreeMap<char, char>,
    carrier_to_display: BTreeMap<char, char>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EncodingPlanEntry {
    pub character: String,
    pub carrier: String,
    pub cp932_hex: String,
    pub jis_hex: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BmpLayout {
    pixel_offset: usize,
    stride: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FontSlot {
    page: u8,
    cell: u8,
    x: usize,
    y: usize,
}

impl SubstitutionMap {
    pub fn embedded() -> Result<Self> {
        let raw: BTreeMap<String, String> = serde_json::from_str(EMBEDDED_SUBSTITUTIONS)
            .map_err(|error| format!("内置 subs_cn_jp.json 无法解析: {error}"))?;
        let mut mappings = HashMap::with_capacity(raw.len());
        let mut carriers = BTreeMap::new();
        for (source, carrier) in raw {
            let source_chars = source.chars().collect::<Vec<_>>();
            let carrier_chars = carrier.chars().collect::<Vec<_>>();
            if source_chars.len() != 1 || carrier_chars.len() != 1 {
                return Err("内置 subs_cn_jp.json 必须每侧恰好一个字符".to_string());
            }
            let source = source_chars[0];
            let carrier = carrier_chars[0];
            if let Some(previous) = carriers.insert(carrier, source) {
                return Err(format!(
                    "内置字形载体 {carrier} 同时分配给 {previous} 和 {source}"
                ));
            }
            if !has_loaded_np2_slot(carrier) {
                return Err(format!("内置载体 {carrier} 不在 NP2 已加载双字节字库页"));
            }
            mappings.insert(source, carrier);
        }
        Ok(Self { mappings })
    }

    pub fn carrier_for(&self, original: char, normalized: char) -> Option<char> {
        self.mappings
            .get(&normalized)
            .copied()
            .or_else(|| self.mappings.get(&original).copied())
    }

    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }

    fn candidate_carriers(&self) -> Vec<char> {
        let mut carriers = self.mappings.values().copied().collect::<Vec<_>>();
        carriers.sort_unstable();
        carriers.dedup();
        carriers
    }
}

impl EncodingPlan {
    pub fn build<'a>(texts: impl IntoIterator<Item = &'a str>) -> Result<Self> {
        let substitutions = SubstitutionMap::embedded()?;
        let mut characters = BTreeSet::new();
        for text in texts {
            for character in text.chars() {
                let normalized = normalize_character(character)?;
                if normalized != '　' {
                    characters.insert(normalized);
                }
            }
        }

        let mut display_to_carrier = BTreeMap::new();
        let mut carrier_to_display = BTreeMap::new();
        let mut used = HashSet::new();

        // 原生双字节字符优先占用自己的槽位，之后才给代换字符分配载体。
        // 这样日文原字与简体中文同时出现时，不会把原字的显示含义覆盖掉。
        for character in characters.iter().copied() {
            if has_loaded_np2_slot(character) {
                display_to_carrier.insert(character, character);
                carrier_to_display.insert(character, character);
                used.insert(character);
            }
        }

        let fallback = substitutions.candidate_carriers();
        for character in characters {
            if display_to_carrier.contains_key(&character) {
                continue;
            }
            let preferred = substitutions.carrier_for(character, character);
            let carrier = preferred
                .filter(|candidate| !used.contains(candidate))
                .or_else(|| {
                    fallback
                        .iter()
                        .copied()
                        .find(|candidate| !used.contains(candidate))
                })
                .ok_or_else(|| {
                    format!(
                        "字符槽位不足，无法为 {character} (U+{:04X}) 分配载体",
                        character as u32
                    )
                })?;
            display_to_carrier.insert(character, carrier);
            carrier_to_display.insert(carrier, character);
            used.insert(carrier);
        }
        Ok(Self {
            display_to_carrier,
            carrier_to_display,
        })
    }

    pub fn normalize_text(&self, text: &str) -> Result<String> {
        text.chars().map(normalize_character).collect()
    }

    pub fn carrier_for(&self, character: char) -> Result<char> {
        let normalized = normalize_character(character)?;
        if normalized == '　' {
            return Ok(normalized);
        }
        self.display_to_carrier
            .get(&normalized)
            .copied()
            .ok_or_else(|| {
                format!(
                    "字符 {normalized} (U+{:04X}) 不在本次字槽计划中",
                    normalized as u32
                )
            })
    }

    pub fn display_for_carrier(&self, carrier: char) -> char {
        self.carrier_to_display
            .get(&carrier)
            .copied()
            .unwrap_or(carrier)
    }

    pub fn decode_carriers(&self, text: &str) -> String {
        text.chars()
            .map(|character| self.display_for_carrier(character))
            .collect()
    }

    pub fn requests(&self) -> Vec<FontPatchRequest> {
        self.display_to_carrier
            .iter()
            .map(|(replacement, carrier)| FontPatchRequest {
                carrier: *carrier,
                replacement: *replacement,
            })
            .collect()
    }

    pub fn manifest_entries(&self) -> Result<Vec<EncodingPlanEntry>> {
        self.display_to_carrier
            .iter()
            .map(|(character, carrier)| {
                let cp932 = cp932_for_carrier(*carrier)?;
                let jis = cp932_to_jis(cp932)?;
                Ok(EncodingPlanEntry {
                    character: character.to_string(),
                    carrier: carrier.to_string(),
                    cp932_hex: format!("{:02X}{:02X}", cp932[0], cp932[1]),
                    jis_hex: format!("{:02X}{:02X}", jis[0], jis[1]),
                })
            })
            .collect()
    }
}

pub fn normalize_character(character: char) -> Result<char> {
    match character {
        ' ' | '　' => Ok('　'),
        '\0' | '\r' | '\n' => Err(format!(
            "文本包含不允许的控制字符 U+{:04X}",
            character as u32
        )),
        '!'..='~' => Ok(
            char::from_u32(0xFF01 + u32::from(character) - u32::from('!'))
                .expect("fullwidth ASCII mapping"),
        ),
        other if other.is_control() => {
            Err(format!("文本包含不允许的控制字符 U+{:04X}", other as u32))
        }
        other => Ok(other),
    }
}

pub fn cp932_for_carrier(carrier: char) -> Result<[u8; 2]> {
    let encoded_text = carrier.to_string();
    let (encoded, _, had_errors) = SHIFT_JIS.encode(&encoded_text);
    if had_errors || encoded.len() != 2 {
        return Err(format!("载体 {carrier} 不是双字节 CP932 字符"));
    }
    Ok([encoded[0], encoded[1]])
}

pub fn cp932_to_jis(cp932: [u8; 2]) -> Result<[u8; 2]> {
    let lead = cp932[0];
    let mut trail = cp932[1];
    if !((0x81..=0x9F).contains(&lead) || (0xE0..=0xEF).contains(&lead))
        || !((0x40..=0x7E).contains(&trail) || (0x80..=0xFC).contains(&trail))
        || trail == 0x7F
    {
        return Err(format!("CP932 {:02X}{:02X} 无法转换为 JIS", lead, trail));
    }
    let row_base = if lead <= 0x9F {
        lead - 0x81
    } else {
        lead - 0xC1
    };
    let row = row_base * 2 + 0x21 + u8::from(trail >= 0x9F);
    let cell = if trail >= 0x9F {
        trail - 0x7E
    } else {
        if trail > 0x7F {
            trail -= 1;
        }
        trail - 0x1F
    };
    Ok([row, cell])
}

pub fn jis_to_cp932(jis: [u8; 2]) -> Result<[u8; 2]> {
    let row = jis[0];
    let cell = jis[1];
    if !(0x21..=0x7E).contains(&row) || !(0x21..=0x7E).contains(&cell) {
        return Err(format!("JIS {:02X}{:02X} 不在 0x21..0x7E", row, cell));
    }
    let row_index = row - 0x21;
    let mut lead = row_index / 2 + 0x81;
    if lead > 0x9F {
        lead += 0x40;
    }
    let trail = if row_index.is_multiple_of(2) {
        let mut value = cell + 0x1F;
        if value >= 0x7F {
            value += 1;
        }
        value
    } else {
        cell + 0x7E
    };
    Ok([lead, trail])
}

pub fn embedded_font_sha256() -> String {
    crate::sha256_hex(EMBEDDED_FONT)
}

pub fn prepare_font(
    requests: &[FontPatchRequest],
    literal_characters: &BTreeSet<char>,
) -> Result<FontBuild> {
    let layout = validate_font_tmp(EMBEDDED_FONT)?;
    let mut coalesced = BTreeMap::<char, char>::new();
    for request in requests {
        if let Some(previous) = coalesced.insert(request.carrier, request.replacement) {
            if previous != request.replacement {
                return Err(format!(
                    "载体字符 {} 同时被要求显示 {} 和 {}",
                    request.carrier, previous, request.replacement
                ));
            }
        }
    }
    for carrier in coalesced.keys() {
        if literal_characters.contains(carrier) {
            return Err(format!(
                "载体字符 {carrier} 同时作为原义文字出现；重绘会全局改变它的显示"
            ));
        }
    }

    let mut output = EMBEDDED_FONT.to_vec();
    let mut allowed = vec![false; output.len()];
    for (carrier, replacement) in &coalesced {
        let slot = slot_for_carrier(*carrier)?;
        let glyph = render_glyph(*replacement, FONT_FACE)?;
        write_slot(&mut output, layout, slot, &glyph)?;
        mark_slot_bytes(&mut allowed, layout, slot)?;
        if read_slot(&output, layout, slot)? != glyph {
            return Err(format!(
                "font.tmp 载体 {carrier} 的 16×16 点阵写入后读回不一致"
            ));
        }
    }
    validate_font_tmp(&output)?;
    for (index, (before, after)) in EMBEDDED_FONT.iter().zip(&output).enumerate() {
        if before != after && !allowed[index] {
            return Err(format!("font.tmp 在非目标槽位 0x{index:X} 发生变化"));
        }
    }
    Ok(FontBuild {
        bytes: output,
        patched_glyphs: coalesced.len(),
    })
}

pub fn has_loaded_np2_slot(carrier: char) -> bool {
    slot_for_carrier(carrier).is_ok()
}

fn validate_font_tmp(bytes: &[u8]) -> Result<BmpLayout> {
    if bytes.len() != BMP_FILE_SIZE || bytes.get(..2) != Some(b"BM") {
        return Err(format!("内置 font.tmp 不是预期的 {BMP_FILE_SIZE} 字节 BMP"));
    }
    if read_u32(bytes, 10)? as usize != BMP_PIXEL_OFFSET
        || read_u32(bytes, 14)? != 40
        || read_i32(bytes, 18)? != BMP_WIDTH as i32
        || read_i32(bytes, 22)? != BMP_HEIGHT as i32
        || read_u16(bytes, 26)? != 1
        || read_u16(bytes, 28)? != 1
        || read_u32(bytes, 30)? != 0
        || read_u32(bytes, 34)? as usize != BMP_STRIDE * BMP_HEIGHT
        || bytes[54..58] != [0, 0, 0, 0]
        || bytes[58..62] != [255, 255, 255, 0]
        || BMP_PIXEL_OFFSET + BMP_STRIDE * BMP_HEIGHT != bytes.len()
    {
        return Err("font.tmp 的 2048×2048、1bpp、底向上 BMP 结构不匹配".to_string());
    }
    Ok(BmpLayout {
        pixel_offset: BMP_PIXEL_OFFSET,
        stride: BMP_STRIDE,
    })
}

fn slot_for_carrier(carrier: char) -> Result<FontSlot> {
    let text = carrier.to_string();
    let (encoded, _, had_errors) = SHIFT_JIS.encode(&text);
    if had_errors || encoded.len() != 2 {
        return Err(format!("载体 {carrier} 不是双字节 CP932 字符"));
    }
    let lead = encoded[0];
    let mut trail = encoded[1];
    if !((0x81..=0x9F).contains(&lead) || (0xE0..=0xEF).contains(&lead))
        || !((0x40..=0x7E).contains(&trail) || (0x80..=0xFC).contains(&trail))
        || trail == 0x7F
    {
        return Err(format!(
            "载体 {carrier} 编码为不可用 CP932 字节 {lead:02X}{trail:02X}"
        ));
    }
    let row_base = if lead <= 0x9F {
        lead - 0x81
    } else {
        lead - 0xC1
    };
    let row = row_base * 2 + 0x21 + u8::from(trail >= 0x9F);
    let cell = if trail >= 0x9F {
        trail - 0x7E
    } else {
        if trail > 0x7F {
            trail -= 1;
        }
        trail - 0x1F
    };
    let page = row
        .checked_sub(0x20)
        .ok_or_else(|| format!("载体 {carrier} 位于 JIS 0x21 之前"))?;
    if !((0x01..=0x55).contains(&page) || (0x58..=0x5F).contains(&page))
        || !(0x01..=0x7F).contains(&cell)
    {
        return Err(format!(
            "载体 {carrier} 位于 NP2 未加载页 page=0x{page:02X} cell=0x{cell:02X}"
        ));
    }
    let x = usize::from(page) * GLYPH_WIDTH;
    let y = usize::from(cell) * GLYPH_HEIGHT;
    if x + GLYPH_WIDTH > BMP_WIDTH || y + GLYPH_HEIGHT > BMP_HEIGHT {
        return Err(format!("载体 {carrier} 的 font.tmp 坐标越界"));
    }
    Ok(FontSlot { page, cell, x, y })
}

fn write_slot(
    bytes: &mut [u8],
    layout: BmpLayout,
    slot: FontSlot,
    glyph: &[u8; GLYPH_BYTES],
) -> Result<()> {
    for row in 0..GLYPH_HEIGHT {
        let offset = row_offset(layout, slot, row)?;
        bytes[offset..offset + 2].copy_from_slice(&glyph[row * 2..row * 2 + 2]);
    }
    Ok(())
}

fn read_slot(bytes: &[u8], layout: BmpLayout, slot: FontSlot) -> Result<[u8; GLYPH_BYTES]> {
    let mut glyph = [0u8; GLYPH_BYTES];
    for row in 0..GLYPH_HEIGHT {
        let offset = row_offset(layout, slot, row)?;
        glyph[row * 2..row * 2 + 2].copy_from_slice(&bytes[offset..offset + 2]);
    }
    Ok(glyph)
}

fn mark_slot_bytes(allowed: &mut [bool], layout: BmpLayout, slot: FontSlot) -> Result<()> {
    for row in 0..GLYPH_HEIGHT {
        let offset = row_offset(layout, slot, row)?;
        allowed[offset] = true;
        allowed[offset + 1] = true;
    }
    Ok(())
}

fn row_offset(layout: BmpLayout, slot: FontSlot, row: usize) -> Result<usize> {
    let atlas_y = slot.y + row;
    let storage_y = BMP_HEIGHT
        .checked_sub(1 + atlas_y)
        .ok_or_else(|| "font.tmp 字形行越界".to_string())?;
    layout
        .pixel_offset
        .checked_add(storage_y * layout.stride)
        .and_then(|offset| offset.checked_add(slot.x / 8))
        .filter(|offset| offset + 2 <= BMP_FILE_SIZE)
        .ok_or_else(|| "font.tmp 字形偏移溢出".to_string())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| format!("font.tmp 0x{offset:X} 缺少 u16"))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| format!("font.tmp 0x{offset:X} 缺少 u32"))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32> {
    Ok(read_u32(bytes, offset)? as i32)
}

#[cfg(windows)]
fn render_glyph(replacement: char, face: &str) -> Result<[u8; GLYPH_BYTES]> {
    render_glyph_windows(replacement, face)
}

#[cfg(not(windows))]
fn render_glyph(_replacement: char, _face: &str) -> Result<[u8; GLYPH_BYTES]> {
    Err("font.tmp 重绘需要 Windows GDI".to_string())
}

#[cfg(windows)]
mod windows_gdi {
    use std::ffi::c_void;

    pub type Hdc = *mut c_void;
    pub type Hfont = *mut c_void;
    pub type Hbitmap = *mut c_void;
    pub type Hgdiobj = *mut c_void;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct BitmapInfoHeader {
        pub size: u32,
        pub width: i32,
        pub height: i32,
        pub planes: u16,
        pub bit_count: u16,
        pub compression: u32,
        pub size_image: u32,
        pub x_pels_per_meter: i32,
        pub y_pels_per_meter: i32,
        pub clr_used: u32,
        pub clr_important: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct RgbQuad {
        pub blue: u8,
        pub green: u8,
        pub red: u8,
        pub reserved: u8,
    }

    #[repr(C)]
    pub struct BitmapInfo {
        pub header: BitmapInfoHeader,
        pub colors: [RgbQuad; 2],
    }

    pub const DIB_RGB_COLORS: u32 = 0;
    pub const DEFAULT_CHARSET: u32 = 1;
    pub const OUT_DEFAULT_PRECIS: u32 = 0;
    pub const CLIP_DEFAULT_PRECIS: u32 = 0;
    pub const NONANTIALIASED_QUALITY: u32 = 3;
    pub const FIXED_PITCH: u32 = 1;
    pub const FW_NORMAL: i32 = 400;
    pub const OPAQUE: i32 = 2;
    pub const CLR_INVALID: u32 = 0xFFFF_FFFF;

    #[link(name = "gdi32")]
    extern "system" {
        pub fn CreateCompatibleDC(hdc: Hdc) -> Hdc;
        pub fn DeleteDC(hdc: Hdc) -> i32;
        pub fn CreateDIBSection(
            hdc: Hdc,
            bitmap_info: *const BitmapInfo,
            usage: u32,
            bits: *mut *mut c_void,
            section: *mut c_void,
            offset: u32,
        ) -> Hbitmap;
        pub fn DeleteObject(object: Hgdiobj) -> i32;
        pub fn SelectObject(hdc: Hdc, object: Hgdiobj) -> Hgdiobj;
        pub fn CreateFontW(
            height: i32,
            width: i32,
            escapement: i32,
            orientation: i32,
            weight: i32,
            italic: u32,
            underline: u32,
            strike_out: u32,
            charset: u32,
            output_precision: u32,
            clip_precision: u32,
            quality: u32,
            pitch_and_family: u32,
            face: *const u16,
        ) -> Hfont;
        pub fn SetBkColor(hdc: Hdc, color: u32) -> u32;
        pub fn SetTextColor(hdc: Hdc, color: u32) -> u32;
        pub fn SetBkMode(hdc: Hdc, mode: i32) -> i32;
        pub fn TextOutW(hdc: Hdc, x: i32, y: i32, text: *const u16, count: i32) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        pub fn GetLastError() -> u32;
    }
}

#[cfg(windows)]
fn render_glyph_windows(replacement: char, face: &str) -> Result<[u8; GLYPH_BYTES]> {
    use std::ffi::c_void;
    use std::ptr;
    use windows_gdi::*;

    if replacement as u32 > 0xFFFF || replacement.is_control() {
        return Err(format!(
            "字符 U+{:04X} 不能作为一个 16×16 BMP 字形渲染",
            replacement as u32
        ));
    }
    let mut face_w = face.encode_utf16().collect::<Vec<_>>();
    face_w.push(0);
    let text_w = [replacement as u16];
    let bitmap_info = BitmapInfo {
        header: BitmapInfoHeader {
            size: 40,
            width: GLYPH_WIDTH as i32,
            height: -(GLYPH_HEIGHT as i32),
            planes: 1,
            bit_count: 1,
            compression: 0,
            size_image: (GLYPH_HEIGHT * 4) as u32,
            x_pels_per_meter: 0,
            y_pels_per_meter: 0,
            clr_used: 2,
            clr_important: 2,
        },
        colors: [
            RgbQuad {
                blue: 0,
                green: 0,
                red: 0,
                reserved: 0,
            },
            RgbQuad {
                blue: 255,
                green: 255,
                red: 255,
                reserved: 0,
            },
        ],
    };

    let mut dc: Hdc = ptr::null_mut();
    let mut bitmap: Hbitmap = ptr::null_mut();
    let mut font: Hfont = ptr::null_mut();
    let mut old_bitmap: Hgdiobj = ptr::null_mut();
    let mut old_font: Hgdiobj = ptr::null_mut();
    let result = (|| unsafe {
        dc = CreateCompatibleDC(ptr::null_mut());
        if dc.is_null() {
            return Err(gdi_error("CreateCompatibleDC"));
        }
        let mut bits: *mut c_void = ptr::null_mut();
        bitmap = CreateDIBSection(
            dc,
            &bitmap_info,
            DIB_RGB_COLORS,
            &mut bits,
            ptr::null_mut(),
            0,
        );
        if bitmap.is_null() || bits.is_null() {
            return Err(gdi_error("CreateDIBSection"));
        }
        std::slice::from_raw_parts_mut(bits as *mut u8, GLYPH_HEIGHT * 4).fill(0xFF);
        font = CreateFontW(
            GLYPH_HEIGHT as i32,
            0,
            0,
            0,
            FW_NORMAL,
            0,
            0,
            0,
            DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            NONANTIALIASED_QUALITY,
            FIXED_PITCH,
            face_w.as_ptr(),
        );
        if font.is_null() {
            return Err(gdi_error("CreateFontW"));
        }
        old_bitmap = SelectObject(dc, bitmap as Hgdiobj);
        old_font = SelectObject(dc, font as Hgdiobj);
        if old_bitmap.is_null() || old_font.is_null() {
            return Err(gdi_error("SelectObject"));
        }
        if SetBkMode(dc, OPAQUE) == 0
            || SetBkColor(dc, 0x00FF_FFFF) == CLR_INVALID
            || SetTextColor(dc, 0x0000_0000) == CLR_INVALID
            || TextOutW(dc, 0, 0, text_w.as_ptr(), 1) == 0
        {
            return Err(gdi_error("TextOutW"));
        }
        let raw = std::slice::from_raw_parts(bits as *const u8, GLYPH_HEIGHT * 4);
        let mut glyph = [0u8; GLYPH_BYTES];
        for row in 0..GLYPH_HEIGHT {
            glyph[row * 2..row * 2 + 2].copy_from_slice(&raw[row * 4..row * 4 + 2]);
        }
        Ok(glyph)
    })();
    unsafe {
        if !old_font.is_null() {
            let _ = SelectObject(dc, old_font);
        }
        if !old_bitmap.is_null() {
            let _ = SelectObject(dc, old_bitmap);
        }
        if !font.is_null() {
            let _ = DeleteObject(font as Hgdiobj);
        }
        if !bitmap.is_null() {
            let _ = DeleteObject(bitmap as Hgdiobj);
        }
        if !dc.is_null() {
            let _ = DeleteDC(dc);
        }
    }
    result
}

#[cfg(windows)]
fn gdi_error(operation: &str) -> String {
    let code = unsafe { windows_gdi::GetLastError() };
    format!("{operation} 失败 (GetLastError={code})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_assets_are_valid() {
        assert_eq!(validate_font_tmp(EMBEDDED_FONT).unwrap().stride, BMP_STRIDE);
        let mappings = SubstitutionMap::embedded().expect("embedded substitutions");
        assert_eq!(mappings.len(), 3025);
        assert_eq!(mappings.carrier_for('你', '你'), Some('凜'));
    }

    #[test]
    fn verified_rin_slot_coordinates_match() {
        let slot = slot_for_carrier('凛').expect("凛 slot");
        assert_eq!(
            (slot.page, slot.cell, slot.x, slot.y),
            (0x31, 0x5B, 784, 1456)
        );
    }

    #[cfg(windows)]
    #[test]
    fn redraws_embedded_font_in_one_slot() {
        let build = prepare_font(
            &[FontPatchRequest {
                carrier: '凜',
                replacement: '你',
            }],
            &BTreeSet::new(),
        )
        .expect("redraw embedded font");
        assert_eq!(build.bytes.len(), EMBEDDED_FONT.len());
        assert_eq!(build.patched_glyphs, 1);
        assert_ne!(build.bytes, EMBEDDED_FONT);
    }
}
