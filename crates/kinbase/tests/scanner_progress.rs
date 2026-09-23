use std::env;
use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use kinbase::scanner::{scanner_with, Registry};

const CHILD_TEST_NAME: &str = "scanner_case_child";
const ENV_TEXT: &str = "KINBASE_SCANNER_CASE_TEXT";
const ENV_EXPECT: &str = "KINBASE_SCANNER_CASE_EXPECT_BLOCK";
const CHILD_MARKER: &str = "KINBASE_SCANNER_CHILD_CASE_COMPLETED";
const CASE_DEADLINE: Duration = Duration::from_secs(5);

/// Child-side helper. Does nothing unless the parent set the case env vars.
#[test]
fn scanner_case_child() {
    let text = match env::var(ENV_TEXT) {
        Ok(t) => t,
        Err(_) => return,
    };
    let expect = match env::var(ENV_EXPECT).as_deref() {
        Ok("1") => true,
        Ok("0") => false,
        other => panic!("child: invalid {} value: {:?}", ENV_EXPECT, other),
    };
    let result = scanner_with(&text, &Registry::default());
    let preview: String = text.chars().take(120).collect();
    assert_eq!(
        result.hard_block, expect,
        "hard_block mismatch for case (first 120 chars): {:?}",
        preview
    );
    println!("{}", CHILD_MARKER);
}

fn is_child() -> bool {
    env::var_os(ENV_TEXT).is_some()
}

fn drain<R: Read + Send + 'static>(reader: Option<R>) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut r) = reader {
            let _ = r.read_to_end(&mut buf);
        }
        String::from_utf8_lossy(&buf).into_owned()
    })
}

fn wait_with_deadline(child: &mut Child, deadline: Duration) -> Option<ExitStatus> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {
                if start.elapsed() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("try_wait failed: {}", e);
            }
        }
    }
}

fn run_case(name: &str, text: &str, expect_block: bool) -> Result<(), String> {
    let exe = env::current_exe().map_err(|e| format!("{}: current_exe failed: {}", name, e))?;
    let mut child = Command::new(exe)
        .arg(CHILD_TEST_NAME)
        .arg("--exact")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(ENV_TEXT, text)
        .env(ENV_EXPECT, if expect_block { "1" } else { "0" })
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{}: spawn failed: {}", name, e))?;

    let out = drain(child.stdout.take());
    let err = drain(child.stderr.take());
    let status = wait_with_deadline(&mut child, CASE_DEADLINE);
    let stdout = out.join().unwrap_or_default();
    let stderr = err.join().unwrap_or_default();

    match status {
        None => Err(format!(
            "{}: scan did not terminate within {:?} (child killed)",
            name, CASE_DEADLINE
        )),
        Some(s) if !s.success() => Err(format!(
            "{}: child failed ({}), expected hard_block={}\nstdout:\n{}\nstderr:\n{}",
            name, s, expect_block, stdout, stderr
        )),
        Some(_) if !stdout.contains(CHILD_MARKER) => Err(format!(
            "{}: child exited successfully but helper test did not run\nstdout:\n{}",
            name, stdout
        )),
        Some(_) => Ok(()),
    }
}

fn run_table(cases: &[(&str, String, bool)]) {
    if is_child() {
        return;
    }
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|(name, text, expect)| run_case(name, text, *expect).err())
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {} cases failed:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n\n")
    );
}

#[test]
fn harmless_word_adjacent_punctuation_is_not_blocked() {
    let cases: Vec<(&str, String, bool)> = vec![
        ("candidate_round", "candidate15+round34".into(), false),
        ("status_ok", "status(ok)".into(), false),
        ("plus_at_start", "+retry the job".into(), false),
        ("paren_at_start", "(see notes below".into(), false),
        ("plus_at_end", "merge branch feature+".into(), false),
        ("paren_at_end", "call the function(".into(), false),
        ("plus_after_accented", "café+crème".into(), false),
        ("paren_after_accented", "naïve(approach)".into(), false),
        ("plus_after_cjk", "日本語+テスト".into(), false),
        ("paren_after_cyrillic", "проверка(готово)".into(), false),
        ("paren_after_umlaut_end", "Übergröße(".into(), false),
        ("cpp", "We compile with g++ and clang++ for C++ builds.".into(), false),
        ("chained_plus", "a+b+c+d+e".into(), false),
        ("nested_parens", "f(g(h(x)))".into(), false),
        ("semver_build", "released v1.2.3+build45 today".into(), false),
        ("retry_backoff", "retry(3)+backoff(250ms)".into(), false),
        ("map_filter", "map(fn)+filter(pred) then collect()".into(), false),
        ("rev_note", "build 2024(rev 3) passed".into(), false),
        ("identifier_not_phone", "ABC-123-456-7890".into(), false),
        (
            "identifier_in_prose",
            "Ticket ABC-123-456-7890 was closed after review.".into(),
            false,
        ),
        (
            "ordinary_prose",
            "The candidate15+round34 run finished with status(ok); next we tune \
             batch(size)+lr(0.01) and rerun eval(split=dev)."
                .into(),
            false,
        ),
        ("repeated_plus", "+".repeat(5000), false),
        ("repeated_open_paren", "(".repeat(5000), false),
        ("repeated_plus_paren", "+(".repeat(5000), false),
        ("repeated_word_plus", "word+".repeat(3000), false),
        ("repeated_word_paren", "status(".repeat(3000), false),
        ("repeated_unicode_plus", "ñandú+".repeat(3000), false),
        ("repeated_tokens", "candidate15+round34 status(ok) ".repeat(1000), false),
        ("mixed_punct_run", "word+(+(+((++(( end".into(), false),
        ("empty", String::new(), false),
    ];
    run_table(&cases);
}

#[test]
fn genuine_phone_numbers_are_hard_blocked() {
    let cases: Vec<(&str, String, bool)> = vec![
        ("nanp_parens", "Call me at (415) 867-5309 tomorrow.".into(), true),
        ("nanp_dashes", "Phone: 415-867-5309".into(), true),
        ("nanp_dots", "reach support at 212.736.5000 anytime".into(), true),
        ("nanp_plus1_spaces", "Office line +1 415 867 5309.".into(), true),
        ("nanp_plus1_parens", "My number is +1 (212) 736-5000.".into(), true),
        ("e164_us", "Text +14158675309 when ready.".into(), true),
        ("e164_uk", "international office: +442071838750".into(), true),
        ("e164_de", "mobile +4915123456789 (evenings)".into(), true),
        ("phone_at_start", "(415) 867-5309 is the on-call number".into(), true),
        ("phone_at_end", "on-call number is 415-867-5309".into(), true),
        (
            "phone_after_unicode",
            "Contactez José au (514) 872-1111 demain.".into(),
            true,
        ),
        (
            "phone_amid_harmless",
            "candidate15+round34 status(ok); escalate to +1 415 867 5309".into(),
            true,
        ),
    ];
    run_table(&cases);
}
