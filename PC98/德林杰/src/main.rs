use anyhow::{bail, Context, Result};
use drrnger_d88_tool::{extract_localization, pack_localization, restore_original_files, unpack};
use std::env;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        return interactive(None);
    }
    if is_help(&args[0]) {
        print_help();
        return Ok(());
    }
    if args.len() == 1 && !args[0].to_string_lossy().starts_with('-') {
        return interactive(Some(PathBuf::from(&args[0])));
    }
    if args[0] == "restore-files" {
        let options = Options::parse(&args[1..])?;
        if options.inputs.len() != 1 {
            bail!("restore-files requires exactly one --input system-disk D88");
        }
        if options.overwrite {
            bail!("restore-files does not overwrite directories; choose a new --output path");
        }
        return run_restore_files(&options.inputs[0], &options.output);
    }
    if args[0] == "extract-localization" {
        let options = Options::parse(&args[1..])?;
        if options.inputs.len() != 2 {
            bail!("extract-localization requires exactly two --input D88 images");
        }
        return run_extract_localization(&options.inputs, &options.output, options.overwrite);
    }
    if args[0] == "pack-localization" {
        let options = PackOptions::parse(&args[1..])?;
        return run_pack_localization(
            &options.inputs,
            &options.workspace,
            &options.output,
            options.overwrite,
        );
    }
    if args[0] != "unpack" {
        bail!("unknown command {:?}; use --help", args[0]);
    }
    let options = Options::parse(&args[1..])?;
    run_unpack(&options.inputs, &options.output, options.overwrite)
}

fn run_extract_localization(inputs: &[PathBuf], output: &Path, overwrite: bool) -> Result<()> {
    let report = extract_localization(inputs, output, overwrite)?;
    println!("[extract-localization] documents={}", report.documents);
    println!("[extract-localization] entries={}", report.entries);
    println!("[extract-localization] references={}", report.references);
    println!(
        "[extract-localization] preserved_translations={}",
        report.preserved_translations
    );
    println!("[extract-localization] output={}", report.output.display());
    Ok(())
}

fn run_pack_localization(
    inputs: &[PathBuf],
    workspace: &Path,
    output: &Path,
    overwrite: bool,
) -> Result<()> {
    let report = pack_localization(inputs, workspace, output, overwrite)?;
    println!("[pack-localization] entries={}", report.entries);
    println!(
        "[pack-localization] changed_entries={}",
        report.changed_entries
    );
    println!(
        "[pack-localization] changed_scenarios={}",
        report.changed_scenarios
    );
    println!(
        "[pack-localization] relocated_scenarios={}",
        report.relocated_scenarios
    );
    println!("[pack-localization] redrawn_slots={}", report.redrawn_slots);
    println!("[pack-localization] output={}", report.output.display());
    Ok(())
}

fn run_restore_files(input: &Path, output: &Path) -> Result<()> {
    let report = restore_original_files(input, output)?;
    println!("[restore-files] source_disk={}", report.source_disk);
    println!("[restore-files] VNCOM.BIN sha256={}", report.vncom_sha256);
    println!("[restore-files] DIRBLK.BIN sha256={}", report.dirblk_sha256);
    println!("[restore-files] output={}", report.output.display());
    Ok(())
}

fn run_unpack(inputs: &[PathBuf], output: &Path, overwrite: bool) -> Result<()> {
    let report = unpack(inputs, output, overwrite)?;
    println!("[unpack] disks={}", report.disks);
    println!("[unpack] tracks={}", report.tracks);
    println!("[unpack] sectors={}", report.sectors);
    println!("[unpack] logical_bytes={}", report.logical_bytes);
    println!("[unpack] graphics={}", report.graphics);
    println!("[unpack] scenarios={}", report.scenarios);
    println!("[unpack] utf8_text_records={}", report.text_records);
    println!(
        "[unpack] restored_original_files={}",
        report.restored_original_files
    );
    println!("[unpack] output={}", report.output.display());
    Ok(())
}

fn interactive(prefill: Option<PathBuf>) -> Result<()> {
    println!("drrnger-d88-tool interactive");
    loop {
        println!();
        println!("1. 解包《Drrnger》D88 资源");
        println!("0. 退出");
        let Some(choice) = prompt(
            "请选择操作",
            Some(if prefill.is_some() { "1" } else { "0" }),
        )?
        else {
            return Ok(());
        };
        match choice.as_str() {
            "0" => return Ok(()),
            "1" => {
                let default_input = prefill.as_ref().map(|path| path.to_string_lossy());
                let Some(input) = prompt("D88 A 盘输入路径", default_input.as_deref())? else {
                    continue;
                };
                let input = PathBuf::from(strip_drag_quotes(&input));
                let Some(input_b) = prompt("D88 B 盘输入路径", None)? else {
                    continue;
                };
                let input_b = PathBuf::from(strip_drag_quotes(&input_b));
                let default_output = input
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join(format!(
                        "{}_unpacked",
                        input
                            .file_stem()
                            .unwrap_or_else(|| std::ffi::OsStr::new("d88"))
                            .to_string_lossy()
                    ));
                let Some(output) =
                    prompt("输出目录", Some(default_output.to_string_lossy().as_ref()))?
                else {
                    continue;
                };
                let output = PathBuf::from(strip_drag_quotes(&output));
                println!("input={}", input.display());
                println!("output={}", output.display());
                let overwrite = output.exists();
                println!("overwrite={overwrite}");
                let Some(confirm) = prompt("确认执行？y/N", Some("N"))? else {
                    continue;
                };
                if !matches!(confirm.to_ascii_lowercase().as_str(), "y" | "yes") {
                    println!("已取消，未写入文件。");
                    continue;
                }
                match run_unpack(&[input, input_b], &output, overwrite) {
                    Ok(()) => println!("操作完成，已返回主菜单。"),
                    Err(error) => println!("操作未完成：{error:#}"),
                }
            }
            _ => println!("未知操作编号：{choice}"),
        }
    }
}

fn prompt(label: &str, default: Option<&str>) -> Result<Option<String>> {
    if let Some(default) = default {
        print!("{label} [{default}]: ");
    } else {
        print!("{label}: ");
    }
    io::stdout().flush().context("failed to flush prompt")?;
    let mut line = String::new();
    if io::stdin()
        .read_line(&mut line)
        .context("failed to read prompt")?
        == 0
    {
        return Ok(None);
    }
    let value = line.trim();
    if value.is_empty() {
        return Ok(default.map(str::to_owned));
    }
    Ok(Some(value.to_owned()))
}

fn strip_drag_quotes(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(value)
}

fn is_help(value: &OsString) -> bool {
    matches!(value.to_str(), Some("-h" | "--help" | "help"))
}

fn print_help() {
    println!(
        "drrnger-d88-tool - D88 container and native-resource extractor\n\n\
         Usage:\n\
           drrnger-d88-tool\n\
           drrnger-d88-tool <D88_PATH>\n\
           drrnger-d88-tool unpack --input <DISK.D88> [--input <DISK.D88> ...] --output <DIRECTORY> [--overwrite]\n\n\
           drrnger-d88-tool restore-files --input <SYSTEM.D88> --output <NEW_DIRECTORY>\n\n\
           drrnger-d88-tool extract-localization --input <A.D88> --input <B.D88> --output <WORKSPACE> [--overwrite]\n\
           drrnger-d88-tool pack-localization --input <A.D88> --input <B.D88> --workspace <WORKSPACE> --output <REBUILT_DIRECTORY> [--overwrite]\n\n\
         unpack writes complete native resources as CGnnn.DGI and SCnnn.DSC; it does\n\
         not name sector allocations as resource BIN files. restore-files separately\n\
         creates a directory containing exactly VNCOM.BIN and DIRBLK.BIN. Localization\n\
         JSON only permits editing message; pack-localization emits both D88 images and\n\
         the external font.tmp used by the emulator."
    );
}

#[derive(Debug)]
struct PackOptions {
    inputs: Vec<PathBuf>,
    workspace: PathBuf,
    output: PathBuf,
    overwrite: bool,
}

impl PackOptions {
    fn parse(args: &[OsString]) -> Result<Self> {
        let mut inputs = Vec::new();
        let mut workspace = None;
        let mut output = None;
        let mut overwrite = false;
        let mut cursor = 0usize;
        while cursor < args.len() {
            match args[cursor].to_string_lossy().as_ref() {
                "--input" => {
                    cursor += 1;
                    inputs.push(PathBuf::from(
                        args.get(cursor).context("--input requires a path")?,
                    ));
                }
                "--workspace" => {
                    cursor += 1;
                    let value =
                        PathBuf::from(args.get(cursor).context("--workspace requires a path")?);
                    if workspace.replace(value).is_some() {
                        bail!("--workspace may only be specified once");
                    }
                }
                "--output" => {
                    cursor += 1;
                    let value =
                        PathBuf::from(args.get(cursor).context("--output requires a path")?);
                    if output.replace(value).is_some() {
                        bail!("--output may only be specified once");
                    }
                }
                "--overwrite" => {
                    if overwrite {
                        bail!("--overwrite was specified more than once");
                    }
                    overwrite = true;
                }
                option => bail!("unknown option {option:?}"),
            }
            cursor += 1;
        }
        if inputs.len() != 2 {
            bail!("pack-localization requires exactly two --input D88 images");
        }
        Ok(Self {
            inputs,
            workspace: workspace.context("missing --workspace path")?,
            output: output.context("missing --output path")?,
            overwrite,
        })
    }
}

#[derive(Debug)]
struct Options {
    inputs: Vec<PathBuf>,
    output: PathBuf,
    overwrite: bool,
}

impl Options {
    fn parse(args: &[OsString]) -> Result<Self> {
        let mut inputs = Vec::new();
        let mut output = None;
        let mut overwrite = false;
        let mut cursor = 0usize;
        while cursor < args.len() {
            match args[cursor].to_string_lossy().as_ref() {
                "--input" => {
                    cursor += 1;
                    inputs.push(PathBuf::from(
                        args.get(cursor).context("--input requires a path")?,
                    ));
                }
                "--output" => {
                    cursor += 1;
                    let value =
                        PathBuf::from(args.get(cursor).context("--output requires a path")?);
                    if output.replace(value).is_some() {
                        bail!("--output may only be specified once");
                    }
                }
                "--overwrite" => {
                    if overwrite {
                        bail!("--overwrite was specified more than once");
                    }
                    overwrite = true;
                }
                option => bail!("unknown option {option:?}"),
            }
            cursor += 1;
        }
        if inputs.is_empty() {
            bail!("at least one --input path is required");
        }
        Ok(Self {
            inputs,
            output: output.context("missing --output path")?,
            overwrite,
        })
    }
}
