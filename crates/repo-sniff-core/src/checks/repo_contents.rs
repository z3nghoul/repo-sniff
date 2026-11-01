//! Rules of the `repository-contents` family: files whose mere presence in a
//! repository is a risk, judged by their name and their first bytes
//! (`engine = "head"`).
//!
//! What each native executable gets, by content and name (the first matching
//! row wins; every native executable is named by one of the three rules that
//! set `names_executables`, at HIGH or above):
//!
//! | Content | Name | Rule | Level |
//! |---|---|---|---|
//! | native | promises something else: an extension in `NOT_CODE`, a double extension that runs on a double click with a lure inside (`invoice.pdf.exe`, see `LURES`), or bidi or invisible characters | `repo.disguised-executable` | CRITICAL |
//! | PE | `.scr` | `repo.windows-dropper` | HIGH |
//! | native | anything else, or none | `repo.committed-binary` | HIGH |
//! | Java class (validated, see `java_class`) | `.class` | `repo.committed-binary` | MEDIUM |
//! | Python bytecode, Java archive, WebAssembly | see `bytecode` | `repo.committed-binary` | MEDIUM |
//!
//! `repo.windows-dropper` also reports `.lnk` files with a shortcut header and
//! every `.hta`; `repo.windows-script` reports Windows script files by name.
//! Neither replaces the rows above. A symbolic link is judged as disguised
//! when its own name hides the native file it points at; the target is judged
//! as its own file. Nothing here looks inside a binary.

use super::{Ctx, FileIssue, Hit};
use crate::finding::Severity;

/// Extensions that promise a file is not native code: images, documents,
/// media, fonts, archives, text, data and configuration formats, and source
/// or script files. Native code under one of these names is disguised. The
/// list is closed on purpose: extensions that honest repositories use for
/// binary test data (`.bin`, `.dat`, `.data`, `.raw`, `.img`, `.out`, `.o`,
/// `.obj`, `.elf`, `.test`, `.input`, `.golden`, `.sample`) are not in it.
pub const NOT_CODE: &[&str] = &[
    // images
    "png",
    "jpg",
    "jpeg",
    "gif",
    "bmp",
    "ico",
    "icns",
    "svg",
    "webp",
    "tif",
    "tiff",
    "psd",
    "heic",
    "avif", // documents
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "odt",
    "ods",
    "odp",
    "rtf",
    "epub",
    // text, data and configuration
    "txt",
    "md",
    "markdown",
    "rst",
    "csv",
    "tsv",
    "json",
    "jsonc",
    "yaml",
    "yml",
    "toml",
    "xml",
    "html",
    "htm",
    "css",
    "ini",
    "cfg",
    "conf",
    "log",
    "lock",
    "properties",
    "env",
    "pth",
    "start",
    // media
    "mp3",
    "mp4",
    "wav",
    "avi",
    "mov",
    "mkv",
    "flac",
    "ogg",
    "webm",
    "m4a",
    "aac",
    // fonts
    "ttf",
    "otf",
    "woff",
    "woff2",
    "eot", // archives
    "zip",
    "tar",
    "gz",
    "tgz",
    "bz2",
    "xz",
    "7z",
    "rar",
    "zst",
    // source and scripts
    "sh",
    "bash",
    "zsh",
    "fish",
    "py",
    "pyw",
    "rb",
    "pl",
    "pm",
    "php",
    "js",
    "mjs",
    "cjs",
    "ts",
    "tsx",
    "jsx",
    "java",
    "kt",
    "kts",
    "scala",
    "c",
    "h",
    "cc",
    "cpp",
    "cxx",
    "hpp",
    "cs",
    "go",
    "rs",
    "swift",
    "lua",
    "r",
    "ps1",
    "psm1",
    "bat",
    "cmd",
    "vbs",
];

/// Extensions Windows runs on a double click, the outer half of a disguise by
/// double extension (`invoice.pdf.exe`).
const DOUBLE_CLICK: &[&str] = &["exe", "scr", "com", "pif", "cpl"];

/// What a lure pretends to be in a double extension: documents, images,
/// media, archives and plain text. Data and source formats are left out,
/// because dotted names such as `Newtonsoft.Json.dll` or `System.Xml.exe` are
/// ordinary .NET assembly names.
const LURES: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "rtf", "txt", "md", "csv", "html",
    "htm", "png", "jpg", "jpeg", "gif", "bmp", "svg", "webp", "heic", "mp3", "mp4", "avi", "mov",
    "wav", "zip", "rar", "7z",
];

/// Extensions of native executables and libraries. Used only when the bytes
/// of a file are not available, to judge it by name. `.com` is left out:
/// names like `example.com` are common.
const NATIVE_NAMES: &[&str] = &[
    "exe", "dll", "sys", "drv", "efi", "ocx", "cpl", "so", "dylib", "bundle", "node", "pyd", "ko",
    "elf", "appimage",
];

/// Windows command and PowerShell scripts: common build glue in honest
/// repositories, so they keep the rule's base level.
const COMMON_SCRIPTS: &[&str] = &["bat", "cmd", "ps1", "psm1"];

/// Windows Script Host files, rare in honest repositories: MEDIUM.
const WSH_SCRIPTS: &[&str] = &["vbs", "wsf", "wsh"];

/// Script Encoder output, which only hides a script: HIGH.
const ENCODED_SCRIPTS: &[&str] = &["vbe", "jse"];

/// Header of a Windows shortcut: header size 0x4C, then the shell link CLSID
/// 00021401-0000-0000-C000-000000000046.
const LNK_HEADER: [u8; 20] = [
    0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46,
];

/// A file name as Windows treats it: trailing dots and spaces dropped (so
/// `logo.png.` is a `.png`), lowercased.
fn normalized_name(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.trim_end_matches(['.', ' ']).to_lowercase()
}

/// The extension of a normalized name; `None` for no extension or a name
/// that only starts with a dot.
fn extension(name: &str) -> Option<&str> {
    let (stem, extension) = name.rsplit_once('.')?;
    (!stem.is_empty() && !extension.is_empty()).then_some(extension)
}

/// The extension before the last one, as in `invoice.pdf.exe`.
fn inner_extension(name: &str) -> Option<&str> {
    let (stem, _) = name.rsplit_once('.')?;
    // `invoice.pdf          .exe` hides the gap past the edge of a listing.
    extension(stem.trim_end_matches(['.', ' ']))
}

/// Whether the name is a versioned shared library such as `libfoo.so.1.2`.
fn versioned_shared_library(name: &str) -> bool {
    name.split_once(".so.").is_some_and(|(stem, version)| {
        !stem.is_empty()
            && !version.is_empty()
            && version.chars().all(|c| c.is_ascii_digit() || c == '.')
    })
}

/// Bidi controls and invisible characters, which make a name read differently
/// from what it is (`photo<U+202E>gpj.exe` displays as `photoexe.jpg`).
fn has_deceptive_characters(name: &str) -> bool {
    name.chars().any(|c| {
        matches!(
            c as u32,
            0x00AD
                | 0x034F
                | 0x061C
                | 0x115F
                | 0x1160
                | 0x180E
                | 0x200B..=0x200F
                | 0x202A..=0x202E
                | 0x2060..=0x2064
                | 0x2066..=0x2069
                | 0x3164
                | 0xFEFF
                | 0xFFA0
                | 0xE0000..=0xE007F
        )
    })
}

/// What kind of code the first bytes of a file are, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Code {
    /// Native code: ELF, PE, Mach-O or a fat Mach-O binary.
    Native(&'static str),
    /// Bytecode or packaged code that a runtime loads.
    Bytecode(&'static str),
}

/// Recognizes code from a file's first bytes, its normalized name and the
/// native format the scanner found (`Ctx::executable`), so that a check and
/// the scanner's "executable" listing never disagree.
fn code(head: &[u8], name: &str, executable: Option<&'static str>) -> Option<Code> {
    let extension = extension(name);
    if let Some(format) = executable {
        if head.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) {
            return Some(if extension == Some("class") && java_class(head) {
                Code::Bytecode("Java class")
            } else {
                Code::Native("Mach-O fat")
            });
        }
        if head.starts_with(&[0xCA, 0xFE, 0xBA, 0xBF]) {
            return Some(Code::Native("Mach-O fat"));
        }
        return Some(Code::Native(format));
    }
    bytecode(head, extension).map(Code::Bytecode)
}

/// `CAFEBABE` starts both a fat Mach-O binary and a Java class file, and an
/// attacker can make a fat binary look like either. It counts as a Java class
/// only when the version and the start of the constant pool are what a class
/// file needs, no entry of the fat architecture table (as far as the head
/// reaches) names a CPU a loader would run, and (see `code`) the file is named
/// `.class`. Anything else is treated as native code, which keeps it at HIGH.
fn java_class(head: &[u8]) -> bool {
    let field = |at: usize| {
        head.get(at..at + 2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
    };
    let (Some(major), Some(pool), Some(&tag)) = (field(6), field(8), head.get(10)) else {
        return false;
    };
    (45..=80).contains(&major)
        && pool >= 1
        && matches!(tag, 1 | 3..=12 | 15..=20)
        && !names_a_known_cpu(head)
}

/// Whether any 20-byte `fat_arch` entry after the 8-byte fat header, within
/// `head`, has the CPU type of x86, x86-64, ARM, ARM64, ARM64_32, PowerPC or
/// PowerPC 64. A fat binary needs such an entry to run anywhere.
fn names_a_known_cpu(head: &[u8]) -> bool {
    const KNOWN: [u32; 7] = [
        7,
        0x0100_0007,
        12,
        0x0100_000C,
        0x0200_000C,
        18,
        0x0100_0012,
    ];
    head.get(8..)
        .unwrap_or_default()
        .chunks_exact(20)
        .any(|entry| {
            let cpu = u32::from_be_bytes([entry[0], entry[1], entry[2], entry[3]]);
            KNOWN.contains(&cpu)
        })
}

/// Bytecode a runtime loads. Python runs a `.pyc` under any name
/// (`python file`), so a compiled module is recognized by its header alone:
/// a CPython 3 magic number, `\r\n`, and a flags word of 0 to 3. Java archives
/// and WebAssembly need their name as well, because their magic is shared by
/// ordinary zip files or is too short to stand alone.
fn bytecode(head: &[u8], extension: Option<&str>) -> Option<&'static str> {
    let python = match (head.get(0..2), head.get(2..4), head.get(4..8)) {
        (Some(&[lo, hi]), Some(b"\r\n"), Some(&[f0, f1, f2, f3])) => {
            let magic = u16::from_le_bytes([lo, hi]);
            let flags = u32::from_le_bytes([f0, f1, f2, f3]);
            let named = matches!(extension, Some("pyc" | "pyo"));
            (3000..=3999).contains(&magic) && flags <= 3 || named && head.contains(&0)
        }
        _ => false,
    };
    if python {
        return Some("Python bytecode");
    }
    match extension? {
        "jar" | "war" | "ear" if head.starts_with(b"PK\x03\x04") => Some("A Java archive"),
        "wasm" if head.starts_with(b"\0asm") => Some("WebAssembly"),
        _ => None,
    }
}

/// Whether the name of a native file promises something else, and why.
fn disguise(name: &str) -> Option<String> {
    if has_deceptive_characters(name) {
        return Some("its name has bidi or invisible characters".to_string());
    }
    if let Some(extension) = extension(name)
        && NOT_CODE.contains(&extension)
    {
        return Some(format!("its name ends in `.{extension}`"));
    }
    if let (Some(inner), Some(outer)) = (inner_extension(name), extension(name))
        && LURES.contains(&inner)
        && DOUBLE_CLICK.contains(&outer)
    {
        return Some(format!(
            "its name ends in `.{inner}.{outer}`, a double extension"
        ));
    }
    None
}

/// Whether the name of a script or dropper pretends to be a document or an
/// image: bidi or invisible characters, or a lure before the real extension
/// (`invoice.pdf.bat`). Such a file is raised to CRITICAL.
fn lure(name: &str) -> Option<String> {
    if has_deceptive_characters(name) {
        return Some("its name has bidi or invisible characters".to_string());
    }
    let inner = inner_extension(name).filter(|inner| LURES.contains(inner))?;
    Some(format!(
        "its name ends in `.{inner}.{}`, posing as a `.{inner}` file",
        extension(name).unwrap_or_default()
    ))
}

/// "an" before a format whose name starts with a vowel sound.
fn article(format: &str) -> &'static str {
    if format.starts_with(['A', 'E', 'I', 'O', 'U']) {
        "an"
    } else {
        "a"
    }
}

/// Whether `repo.windows-dropper` reports this file as a screen saver, which
/// `repo.committed-binary` then leaves to it.
fn native_screen_saver(name: &str, code: Option<Code>) -> bool {
    extension(name) == Some("scr") && code == Some(Code::Native("PE"))
}

/// The bytes are not there to judge: a file over the size limit that could
/// not be read at all.
fn name_only(ctx: &Ctx<'_>) -> bool {
    ctx.bytes().is_empty() && matches!(ctx.issue, Some(FileIssue::TooLarge { .. }))
}

fn is_symlink(ctx: &Ctx<'_>) -> bool {
    matches!(ctx.issue, Some(FileIssue::Symlink { .. }))
}

fn hit(severity: Severity, reason: String) -> Vec<Hit> {
    vec![Hit {
        line: 1,
        span: None,
        severity,
        reason,
    }]
}

/// Rule `repo.disguised-executable`. Also judges a symbolic link, by its own
/// name and the head of its in-repository target.
pub fn disguised_executable(ctx: &Ctx<'_>) -> Vec<Hit> {
    let name = normalized_name(ctx.path);
    let Some(Code::Native(format)) = code(ctx.bytes(), &name, ctx.executable()) else {
        return Vec::new();
    };
    let Some(why) = disguise(&name) else {
        return Vec::new();
    };
    let what = if is_symlink(ctx) {
        "this symbolic link points at"
    } else {
        "the file is"
    };
    hit(
        ctx.base,
        format!(
            "{what} {} {format} executable, but {why}, which hides what it is; executables do \
             not end up under such names by accident",
            article(format)
        ),
    )
}

/// Rule `repo.committed-binary`.
pub fn committed_binary(ctx: &Ctx<'_>) -> Vec<Hit> {
    if is_symlink(ctx) {
        return Vec::new();
    }
    let name = normalized_name(ctx.path);
    if name_only(ctx) {
        let native = extension(&name).is_some_and(|ext| NATIVE_NAMES.contains(&ext))
            || versioned_shared_library(&name);
        return if native {
            hit(
                ctx.base,
                "the file is named like a native executable or library and is too large to \
                 read; nothing analyzes its code"
                    .to_string(),
            )
        } else {
            Vec::new()
        };
    }
    let code = code(ctx.bytes(), &name, ctx.executable());
    match code {
        Some(Code::Native(_)) if disguise(&name).is_some() || native_screen_saver(&name, code) => {
            Vec::new() // reported as disguised, or as a dropper
        }
        Some(Code::Native(format)) => hit(
            ctx.base,
            format!(
                "{} {format} executable is committed to the repository; it runs native code \
                 that nothing analyzes, so where it comes from has to be checked",
                article(format)
            ),
        ),
        Some(Code::Bytecode(kind)) => hit(
            Severity::Medium,
            format!(
                "{kind} is committed to the repository; a runtime can load it, and nothing \
                 analyzes it"
            ),
        ),
        None => Vec::new(),
    }
}

/// Rule `repo.windows-dropper`. Windows runs these on a double click, but
/// only a `.scr` that is a PE and a `.lnk` with a shortcut header; `mshta`
/// runs an `.hta` whatever it contains. Without the bytes, the name decides.
/// A symbolic link is judged by its own name and the first bytes of its
/// in-repository target, since Windows opens the link by its name.
pub fn windows_dropper(ctx: &Ctx<'_>) -> Vec<Hit> {
    let name = normalized_name(ctx.path);
    let Some(extension) = extension(&name) else {
        return Vec::new();
    };
    let head = ctx.bytes();
    let runs = match extension {
        "hta" => true,
        "lnk" => name_only(ctx) || head.starts_with(&LNK_HEADER),
        "scr" => name_only(ctx) || native_screen_saver(&name, code(head, &name, ctx.executable())),
        _ => false,
    };
    if !runs {
        return Vec::new();
    }
    let reason = format!(
        "Windows runs a `.{extension}` file on a double click; shortcuts, screen savers and \
         HTML applications are a common way to deliver malware"
    );
    match lure(&name) {
        Some(why) => hit(Severity::Critical, format!("{reason}, and {why}")),
        None => hit(ctx.base, reason),
    }
}

/// Rule `repo.windows-script`. A symbolic link is judged by its own name.
pub fn windows_script(ctx: &Ctx<'_>) -> Vec<Hit> {
    let name = normalized_name(ctx.path);
    let Some(extension) = extension(&name) else {
        return Vec::new();
    };
    let (severity, note) = if ENCODED_SCRIPTS.contains(&extension) {
        (
            Severity::High.max(ctx.base),
            "; it is encoded with the Script Encoder, which only serves to hide what it does",
        )
    } else if WSH_SCRIPTS.contains(&extension) {
        (Severity::Medium.max(ctx.base), "")
    } else if COMMON_SCRIPTS.contains(&extension) {
        (ctx.base, "")
    } else {
        return Vec::new();
    };
    let reason =
        format!("a Windows `.{extension}` script; it runs when opened or called on Windows{note}");
    match lure(&name) {
        Some(why) => hit(Severity::Critical, format!("{reason}; {why}")),
        None => hit(severity, reason),
    }
}

/// Absolute targets inside system program folders: a link there is common
/// in an honest checkout (an interpreter in a virtual environment, a build
/// tool's convenience link) and points at programs, not at user data.
const SYSTEM_PROGRAM_DIRS: &[&str] = &[
    "/usr/",
    "/bin/",
    "/sbin/",
    "/lib/",
    "/lib32/",
    "/lib64/",
    "/opt/",
    "/nix/store/",
    "/System/",
    "/Library/",
    "/Applications/",
];

/// Rule `repo.symlink-outside`. A link to the null device is not reported:
/// masked services and similar files point there on purpose.
pub fn symlink_outside(ctx: &Ctx<'_>) -> Vec<Hit> {
    let Some(FileIssue::Symlink {
        target: Some(target),
        resolved: None,
    }) = &ctx.issue
    else {
        return Vec::new();
    };
    if target == "/dev/null" || target.eq_ignore_ascii_case("nul") {
        return Vec::new();
    }
    let system = SYSTEM_PROGRAM_DIRS
        .iter()
        .any(|dir| target.starts_with(dir));
    let severity = if system {
        Severity::Medium.min(ctx.base)
    } else {
        ctx.base
    };
    hit(
        severity,
        format!(
            "this symbolic link points at `{target}`, outside the repository; a tool that \
             follows it reads or writes files elsewhere on the machine"
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::native_format;

    /// `code` with the format the scanner finds for a file of these bytes.
    fn code_of(head: &[u8], name: &str) -> Option<Code> {
        code(head, name, native_format(head, None))
    }

    #[test]
    fn names_are_taken_the_way_windows_sees_them() {
        assert_eq!(normalized_name("a/LOGO.PNG"), "logo.png");
        assert_eq!(normalized_name("photo.jpg."), "photo.jpg");
        assert_eq!(normalized_name("photo.jpg . "), "photo.jpg");
        assert_eq!(extension("invoice.pdf.exe"), Some("exe"));
        assert_eq!(inner_extension("invoice.pdf.exe"), Some("pdf"));
        assert_eq!(extension(".bashrc"), None);
        assert_eq!(extension("tool"), None);
        assert_eq!(inner_extension("tool.exe"), None);
    }

    #[test]
    fn disguises_are_named() {
        assert!(disguise("logo.png").is_some());
        assert!(disguise("invoice.pdf.exe").is_some());
        assert!(disguise("photo\u{202e}gpj.exe").is_some());
        assert!(disguise("app.exe").is_none());
        assert!(disguise("libfoo.so.1.2").is_none());
        assert!(disguise("python3.12.exe").is_none());
        assert!(disguise("data.bin").is_none());
        // Dotted .NET assembly names are not double extensions.
        assert!(disguise("newtonsoft.json.dll").is_none());
        assert!(disguise("system.xml.exe").is_none());
        assert!(disguise("report.pdf.dll").is_none());
        assert!(disguise("photo.jpg.scr").is_some());
    }

    #[test]
    fn versioned_shared_libraries_are_recognized() {
        assert!(versioned_shared_library("libfoo.so.1"));
        assert!(versioned_shared_library("libfoo.so.1.2.3"));
        assert!(!versioned_shared_library("notes.so.txt"));
        assert!(!versioned_shared_library(".so.1"));
    }

    #[test]
    fn cafebabe_is_a_java_class_only_when_it_proves_it() {
        let class = [0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 20, 10, 0];
        let fat = [0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2, 0, 0, 0, 7];
        let padded_fat = [0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 50, 0, 0, 0, 7];
        let no_pool = [0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 0, 10, 0];
        let fat64 = [0xCA, 0xFE, 0xBA, 0xBF, 0, 0, 0, 52, 0, 20, 10, 0];
        assert_eq!(
            code_of(&class, "main.class"),
            Some(Code::Bytecode("Java class"))
        );
        assert_eq!(
            code_of(&class, "main.bin"),
            Some(Code::Native("Mach-O fat"))
        );
        assert_eq!(
            code_of(&fat, "main.class"),
            Some(Code::Native("Mach-O fat"))
        );
        assert_eq!(
            code_of(&padded_fat, "main.class"),
            Some(Code::Native("Mach-O fat"))
        );
        assert_eq!(
            code_of(&no_pool, "main.class"),
            Some(Code::Native("Mach-O fat"))
        );
        assert_eq!(
            code_of(&fat64, "main.class"),
            Some(Code::Native("Mach-O fat"))
        );
        assert_eq!(
            code_of(&[0xCA, 0xFE, 0xBA, 0xBE], "x.class"),
            None,
            "no NUL, not binary"
        );
        // A padded fat binary whose first entry is junk shaped like a class
        // file, with a real x86-64 entry further on.
        let mut tricky = vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 20, 10, 0];
        tricky.resize(8 + 20, 0x41);
        tricky.extend_from_slice(&[0x01, 0, 0, 0x07]);
        tricky.resize(8 + 40, 0);
        assert_eq!(
            code_of(&tricky, "main.class"),
            Some(Code::Native("Mach-O fat"))
        );
    }

    #[test]
    fn native_code_needs_binary_content_and_a_pe_signature() {
        assert_eq!(code_of(b"MZ is a postal code", "a"), None);
        assert_eq!(code_of(b"\x7fELF but text", "a"), None);
        assert_eq!(code_of(b"MZ\x90\0\x03\0", "a"), Some(Code::Native("PE")));
        let mut pe = vec![0u8; 0x48];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3C] = 0x40;
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        assert_eq!(code_of(&pe, "a"), Some(Code::Native("PE")));
        pe[0x40..0x44].copy_from_slice(b"text");
        assert_eq!(
            code_of(&pe, "mz.txt"),
            None,
            "MZ with a NUL but no PE signature"
        );
    }

    #[test]
    fn bytecode_is_recognized_by_header_and_where_needed_by_name() {
        let pyc = b"\xcb\x0d\r\n\0\0\0\0\0\0\0\0";
        assert_eq!(bytecode(pyc, Some("dat")), Some("Python bytecode"));
        assert_eq!(bytecode(b"ab\r\nmore text", Some("txt")), None);
        assert_eq!(
            bytecode(b"ab\r\n\0\0\0\0", Some("pyc")),
            Some("Python bytecode")
        );
        assert_eq!(bytecode(b"PK\x03\x04", Some("jar")), Some("A Java archive"));
        assert_eq!(bytecode(b"PK\x03\x04", Some("zip")), None);
        assert_eq!(bytecode(b"PK\x03\x04", Some("docx")), None);
        assert_eq!(
            bytecode(b"\0asm\x01\0\0\0", Some("wasm")),
            Some("WebAssembly")
        );
        assert_eq!(bytecode(b"text", Some("wasm")), None);
    }

    #[test]
    fn short_and_truncated_headers_never_panic() {
        let headers: [&[u8]; 6] = [
            b"\x7fELF\x02\x01\x01\0",
            b"MZ\x90\0",
            &[0xFE, 0xED, 0xFA, 0xCF, 0, 0, 0, 0],
            &[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 20, 10],
            b"\xcb\x0d\r\n\0\0\0\0",
            b"\0asm\x01\0\0\0",
        ];
        for header in headers {
            for len in 0..=header.len() {
                for name in ["a.class", "a.pyc", "a.png", "a.scr", "a"] {
                    let _ = code_of(&header[..len], name);
                }
            }
        }
    }
}
