//! The repository contents family: committed binaries, disguised
//! executables, Windows droppers and scripts, and symlinks out of the
//! repository.
//!
//! Text fixtures are committed under `tests/fixtures/repo-contents/`. Binary
//! fixtures and symlinks are never committed: each test copies the text
//! fixtures into a temporary folder and generates the rest there. A generated
//! binary is a real header followed by the marker
//! `SYNTHETIC TEST FIXTURE - not functional` and NUL padding; it holds no
//! code and cannot run.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use repo_sniff_core::{Limits, Report, Severity, SkipReason, builtin_rules, scan};

const MARKER: &[u8] = b"SYNTHETIC TEST FIXTURE - not functional";

/// A header, then the marker, then NUL padding.
fn synthetic(header: &[u8]) -> Vec<u8> {
    let mut bytes = header.to_vec();
    bytes.extend_from_slice(MARKER);
    bytes.extend_from_slice(&[0; 64]);
    bytes
}

fn elf() -> Vec<u8> {
    synthetic(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0")
}

/// An `MZ` header whose `e_lfanew` points at a `PE\0\0` signature.
fn pe() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x48];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3C] = 0x40;
    bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
    bytes.extend_from_slice(MARKER);
    bytes.extend_from_slice(&[0; 64]);
    bytes
}

fn mach_o_64() -> Vec<u8> {
    synthetic(&[0xCF, 0xFA, 0xED, 0xFE, 0x07, 0, 0, 0x01])
}

/// A fat Mach-O header with two architectures, the first one x86-64.
fn fat_mach_o() -> Vec<u8> {
    synthetic(&[
        0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2, 0x01, 0, 0, 0x07, 0, 0, 0, 3,
    ])
}

/// A Java class header: version 52, a constant pool of 20 entries whose first
/// one is a method reference (tag 10).
fn java_class() -> Vec<u8> {
    synthetic(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 20, 10, 0, 2])
}

/// The CPython 3.12 magic number, `\r\n`, and a zero flags word.
fn pyc() -> Vec<u8> {
    synthetic(&[0xCB, 0x0D, b'\r', b'\n', 0, 0, 0, 0])
}

fn lnk() -> Vec<u8> {
    synthetic(&[
        0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46,
    ])
}

fn write(root: &Path, relative: &str, contents: &[u8]) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

fn copy_dir(from: &Path, to: &Path) {
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            fs::create_dir_all(&target).unwrap();
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// The committed text fixtures plus every generated binary fixture.
fn fixture_repository() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let committed = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/repo-contents");
    copy_dir(&committed, dir.path());
    let root = dir.path();

    write(root, "positive/bin/tool", &elf());
    write(root, "positive/bin/app.exe", &pe());
    write(root, "positive/lib/libfoo.so.1.2", &elf());
    write(root, "positive/lib/libbar.dylib", &mach_o_64());
    write(root, "positive/lib/universal", &fat_mach_o());
    write(root, "positive/lib/weird.xyz", &pe());
    write(root, "positive/lib/payload.dat", &elf());
    // A dotted .NET assembly name, not a double extension.
    write(root, "positive/lib/Newtonsoft.Json.dll", &pe());
    write(root, "positive/bytecode/Main.class", &java_class());
    write(root, "positive/bytecode/mod.pyc", &pyc());
    write(root, "positive/bytecode/cache.dat", &pyc());
    write(
        root,
        "positive/bytecode/lib.wasm",
        &synthetic(b"\0asm\x01\0\0\0"),
    );
    write(
        root,
        "positive/bytecode/gradle-wrapper.jar",
        &synthetic(b"PK\x03\x04\x14\0\0\0"),
    );
    write(root, "positive/disguised/logo.png", &elf());
    write(root, "positive/disguised/README.txt", &pe());
    write(root, "positive/disguised/install.sh", &elf());
    write(root, "positive/disguised/report.PDF", &mach_o_64());
    write(root, "positive/disguised/data.json", &fat_mach_o());
    write(root, "positive/disguised/invoice.pdf.exe", &pe());
    write(root, "positive/disguised/photo\u{202E}gpj.exe", &pe());
    write(root, "positive/disguised/fake.class", &fat_mach_o());
    write(root, "positive/dropper/invoice.lnk", &lnk());
    write(root, "positive/dropper/screensaver.scr", &pe());

    write(
        root,
        "negative/image/logo.png",
        &synthetic(b"\x89PNG\r\n\x1a\n"),
    );
    write(
        root,
        "negative/archive/archive.docx",
        &synthetic(b"PK\x03\x04\x14\0\0\0"),
    );
    write(
        root,
        "negative/archive/pkg.whl",
        &synthetic(b"PK\x03\x04\x14\0\0\0"),
    );
    write(root, "negative/text/mz-nul.txt", &{
        // Starts with "MZ" and has a NUL, but no PE signature where e_lfanew
        // points: data, not a program.
        let mut bytes = b"MZ text with a stray NUL \0 in it".to_vec();
        bytes.resize(0x48, b' ');
        bytes[0x3C..0x40].copy_from_slice(&[0x40, 0, 0, 0]);
        bytes
    });
    write(
        root,
        "negative/dropper/boot.scr",
        b"setenv bootargs console=ttyS0\n",
    );
    write(
        root,
        "negative/dropper/notes.lnk",
        b"just text in a .lnk file\n",
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let link = |target: &str, at: &str| {
            let path = root.join(at);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            symlink(target, path).unwrap();
        };
        link("/etc/hostname", "positive/links/abs");
        link("../../../outside.txt", "positive/links/up");
        link("/", "positive/links/rootdir");
        link("..\\..\\..\\outside.txt", "positive/links/win-up");
        link("C:\\Windows\\System32", "positive/links/drive");
        link("\\\\host.invalid\\share", "positive/links/unc");
        link("/usr/bin/python3", "positive/links/python");
        link("../bin/tool", "positive/links/logo.png");
        link("../text/mz.txt", "negative/links/inside");
        link("missing.txt", "negative/links/dangling");
        link("/dev/null", "negative/links/null");
    }
    dir
}

type Row = (String, String, Severity);

fn rows(report: &Report) -> BTreeSet<Row> {
    report
        .findings
        .iter()
        .map(|f| {
            let file = f.file.to_string_lossy().replace('\\', "/");
            (file, f.rule_id.clone(), f.severity)
        })
        .collect()
}

fn row(file: &str, rule: &str, severity: Severity) -> Row {
    (file.to_string(), format!("repo.{rule}"), severity)
}

#[test]
fn every_fixture_gets_exactly_its_expected_findings() {
    use Severity::{Critical, High, Low, Medium};
    let dir = fixture_repository();

    let report = scan(dir.path(), &builtin_rules().unwrap(), Limits::default());

    let mut expected: BTreeSet<Row> = [
        row("positive/bin/tool", "committed-binary", High),
        row("positive/bin/app.exe", "committed-binary", High),
        row("positive/lib/libfoo.so.1.2", "committed-binary", High),
        row("positive/lib/libbar.dylib", "committed-binary", High),
        row("positive/lib/universal", "committed-binary", High),
        row("positive/lib/weird.xyz", "committed-binary", High),
        row("positive/lib/payload.dat", "committed-binary", High),
        row("positive/lib/Newtonsoft.Json.dll", "committed-binary", High),
        row("positive/bytecode/Main.class", "committed-binary", Medium),
        row("positive/bytecode/mod.pyc", "committed-binary", Medium),
        row("positive/bytecode/cache.dat", "committed-binary", Medium),
        row("positive/bytecode/lib.wasm", "committed-binary", Medium),
        row(
            "positive/bytecode/gradle-wrapper.jar",
            "committed-binary",
            Medium,
        ),
        row(
            "positive/disguised/logo.png",
            "disguised-executable",
            Critical,
        ),
        row(
            "positive/disguised/README.txt",
            "disguised-executable",
            Critical,
        ),
        row(
            "positive/disguised/install.sh",
            "disguised-executable",
            Critical,
        ),
        row(
            "positive/disguised/report.PDF",
            "disguised-executable",
            Critical,
        ),
        row(
            "positive/disguised/data.json",
            "disguised-executable",
            Critical,
        ),
        row(
            "positive/disguised/invoice.pdf.exe",
            "disguised-executable",
            Critical,
        ),
        row(
            "positive/disguised/photo\u{202E}gpj.exe",
            "disguised-executable",
            Critical,
        ),
        row("positive/disguised/fake.class", "committed-binary", High),
        row("positive/dropper/invoice.lnk", "windows-dropper", High),
        row("positive/dropper/screensaver.scr", "windows-dropper", High),
        row("positive/dropper/update.hta", "windows-dropper", High),
        row("positive/scripts/build.bat", "windows-script", Low),
        row("positive/scripts/setup.cmd", "windows-script", Low),
        row("positive/scripts/deploy.ps1", "windows-script", Low),
        row("positive/scripts/tools.psm1", "windows-script", Low),
        row("positive/scripts/helper.vbs", "windows-script", Medium),
        row("positive/scripts/job.wsf", "windows-script", Medium),
        row("positive/scripts/old.jse", "windows-script", High),
        row("positive/wsh/run.js", "wsh-javascript", Medium),
        row("positive/wsh/fso.js", "wsh-javascript", Medium),
    ]
    .into_iter()
    .collect();
    if cfg!(unix) {
        expected.extend([
            row("positive/links/abs", "symlink-outside", High),
            row("positive/links/up", "symlink-outside", High),
            row("positive/links/rootdir", "symlink-outside", High),
            row("positive/links/win-up", "symlink-outside", High),
            row("positive/links/drive", "symlink-outside", High),
            row("positive/links/unc", "symlink-outside", High),
            row("positive/links/python", "symlink-outside", Medium),
            // The link hides the ELF it points at; the target is reported as
            // a committed binary on its own.
            row("positive/links/logo.png", "disguised-executable", Critical),
        ]);
    }
    let found = rows(&report);
    let missing: Vec<_> = expected.difference(&found).collect();
    let unexpected: Vec<_> = found.difference(&expected).collect();
    assert!(
        missing.is_empty() && unexpected.is_empty(),
        "missing: {missing:#?}\nunexpected: {unexpected:#?}"
    );
}

#[test]
fn reported_executables_are_still_listed_and_the_scan_is_complete() {
    let dir = fixture_repository();

    let report = scan(dir.path(), &builtin_rules().unwrap(), Limits::default());

    assert!(report.is_complete(), "{:?}", report.skipped);
    let executables: Vec<_> = report
        .skipped
        .iter()
        .filter_map(|s| match s.reason {
            SkipReason::Executable { reported, .. } => Some(reported),
            _ => None,
        })
        .collect();
    // Eight committed, seven disguised, the screen saver, and the two files
    // that start with CAFEBABE (the scanner lists every one as executable).
    assert_eq!(executables.len(), 18, "{:?}", report.skipped);
    assert!(executables.iter().all(|&reported| reported));
}

/// Every native header under about forty names is named as an executable at
/// HIGH or above by one of the rules that set `names_executables`, so no name
/// turns an executable into a pass.
#[test]
fn no_name_lets_a_native_executable_through() {
    let names = [
        "tool",
        "a.exe",
        "a.dll",
        "a.so",
        "a.dylib",
        "a.node",
        "a.bin",
        "a.dat",
        "a.o",
        "a.obj",
        "a.elf",
        "a.out",
        "a.png",
        "a.jpg",
        "a.gif",
        "a.pdf",
        "a.txt",
        "a.md",
        "a.json",
        "a.yml",
        "a.xml",
        "a.html",
        "a.zip",
        "a.tar.gz",
        "a.sh",
        "a.py",
        "a.js",
        "a.rs",
        "a.ps1",
        "a.bat",
        "a.cmd",
        "a.vbs",
        "a.jar",
        "a.class",
        "a.pyc",
        "a.wasm",
        "a.hta",
        "a.lnk",
        "a.scr",
        "a.com",
        "a.pth",
        ".npmrc",
        "a.pdf.exe",
        "A.PNG",
    ];
    let headers: [(&str, Vec<u8>); 7] = [
        ("ELF", elf()),
        ("PE", pe()),
        (
            "Mach-O 32",
            synthetic(&[0xFE, 0xED, 0xFA, 0xCE, 0, 0, 0, 7]),
        ),
        ("Mach-O 64", mach_o_64()),
        (
            "Mach-O 64 LE 32",
            synthetic(&[0xCE, 0xFA, 0xED, 0xFE, 7, 0, 0, 0]),
        ),
        ("fat", fat_mach_o()),
        ("fat 64", synthetic(&[0xCA, 0xFE, 0xBA, 0xBF, 0, 0, 0, 1])),
    ];
    let naming = [
        "repo.committed-binary",
        "repo.disguised-executable",
        "repo.windows-dropper",
    ];
    for (format, bytes) in &headers {
        let dir = tempfile::tempdir().unwrap();
        for name in names {
            write(dir.path(), name, bytes);
        }

        let report = scan(dir.path(), &builtin_rules().unwrap(), Limits::default());

        assert!(report.is_complete(), "{format}: {:?}", report.skipped);
        for name in names {
            let named = report.findings.iter().any(|f| {
                f.file.to_string_lossy() == name
                    && naming.contains(&f.rule_id.as_str())
                    && f.severity >= Severity::High
            });
            assert!(named, "{format} named {name} is not reported at HIGH");
        }
    }
}

#[test]
fn large_executables_are_judged_too() {
    let dir = tempfile::tempdir().unwrap();
    let mut big = elf();
    big.resize(4096, 0);
    write(dir.path(), "big.bin", &big);
    write(dir.path(), "huge.png", &big);
    write(
        dir.path(),
        "huge.exe",
        &b"text named like a program\n".repeat(100),
    );

    // big.bin is streamed (over 1 KiB); huge.png and huge.exe are over the
    // size limit, so only their first bytes are read, or nothing at all.
    let streamed = Limits {
        max_buffered_size: 1024,
        max_file_size: 2048,
        ..Limits::default()
    };
    fs::write(dir.path().join("big.bin"), &big[..2000]).unwrap();
    let report = scan(dir.path(), &builtin_rules().unwrap(), streamed);

    let found = rows(&report);
    assert!(found.contains(&row("big.bin", "committed-binary", Severity::High)));
    assert!(found.contains(&row("huge.png", "disguised-executable", Severity::Critical)));
    assert!(
        !found.iter().any(|row| row.0 == "huge.exe"),
        "its first bytes are text: {found:?}"
    );
    // The two files over the limit were not read, so the scan stays
    // inconclusive; the streamed executable does not add to that.
    assert_eq!(report.inconclusive_count(), 2, "{:?}", report.skipped);
}

#[cfg(unix)]
#[test]
fn many_links_to_a_large_file_read_only_its_head() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let mut big = vec![b'x'; 6 * 1024 * 1024];
    big.extend_from_slice(b"\n");
    write(dir.path(), "data/big.txt", &big);
    for index in 0..2000 {
        symlink("data/big.txt", dir.path().join(format!("link{index}"))).unwrap();
    }

    let started = std::time::Instant::now();
    let report = scan(dir.path(), &builtin_rules().unwrap(), Limits::default());

    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(30),
        "took {:?}",
        started.elapsed()
    );
}

/// A PE needs no NUL byte in its first 8 KiB: every DOS header field but `MZ`
/// and `e_lfanew` can be anything, and with all four bytes of `e_lfanew`
/// non-zero its header lies past 16 MiB, where the loader still finds it.
fn pe_without_a_nul_up_front() -> (Vec<u8>, u64) {
    let offset: u64 = 0x0101_0104;
    let mut head = b"MZ".to_vec();
    head.resize(0x3C, b'A');
    head.extend_from_slice(&(offset as u32).to_le_bytes());
    head.extend_from_slice(MARKER);
    head.resize(16 * 1024, b'A');
    (head, offset)
}

fn write_far_pe(path: &Path) {
    use std::io::{Seek, SeekFrom, Write};
    let (head, offset) = pe_without_a_nul_up_front();
    let mut file = fs::File::create(path).unwrap();
    file.write_all(&head).unwrap();
    // The space up to the PE header is left as a hole (zeros), so the test
    // does not write 16 MiB.
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(b"PE\0\0").unwrap();
    file.write_all(MARKER).unwrap();
}

#[test]
fn a_pe_with_no_nul_in_its_first_8_kib_is_still_an_executable() {
    let dir = tempfile::tempdir().unwrap();
    write_far_pe(&dir.path().join("setup.exe"));
    write_far_pe(&dir.path().join("logo.png"));

    let report = scan(dir.path(), &builtin_rules().unwrap(), Limits::default());

    let found = rows(&report);
    assert!(found.contains(&row("setup.exe", "committed-binary", Severity::High)));
    assert!(found.contains(&row("logo.png", "disguised-executable", Severity::Critical)));
    assert!(report.is_complete(), "{:?}", report.skipped);
    let executables = report
        .skipped
        .iter()
        .filter(|s| matches!(s.reason, SkipReason::Executable { reported: true, .. }))
        .count();
    assert_eq!(executables, 2);
}

#[test]
fn an_mz_file_whose_signature_is_missing_is_data_for_the_scanner_and_the_rules() {
    // e_lfanew points at 0x3000, past the first 8 KiB, and there is no PE
    // signature there: both the scanner and the head rules call it data.
    let mut bytes = b"MZ".to_vec();
    bytes.resize(0x3C, 0);
    bytes.extend_from_slice(&0x3000u32.to_le_bytes());
    bytes.extend_from_slice(MARKER);
    bytes.resize(0x3100, 0x11);
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "x.png", &bytes);

    let report = scan(dir.path(), &builtin_rules().unwrap(), Limits::default());

    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert!(
        !report
            .skipped
            .iter()
            .any(|s| matches!(s.reason, SkipReason::Executable { .. })),
        "{:?}",
        report.skipped
    );
}
