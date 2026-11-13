#[allow(unused_imports)]
use super::*;

use std::time::Duration;

use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;

const URI: &str = "https://idp.example.com/device";
const COMPLETE: &str = "https://idp.example.com/device?code=WDJB-MJHT";
const CODE: &str = "WDJB-MJHT";

/// The half-block glyphs `Dense1x2` draws with (full block, upper, lower).
const QR_GLYPHS: [char; 3] = ['\u{2588}', '\u{2580}', '\u{2584}'];

fn start(complete: Option<&str>) -> DeviceStart {
    DeviceStart {
        verification_uri: URI.to_owned(),
        verification_uri_complete: complete.map(str::to_owned),
        user_code: CODE.to_owned(),
        expires_in: Duration::from_secs(600),
    }
}

/// `qrcode`'s default `Dense1x2` rendering of `data` (quiet zone on).
fn qr(data: &str) -> String {
    QrCode::new(data.as_bytes())
        .expect("encodable")
        .render::<Dense1x2>()
        .build()
}

/// The same rendering with dark and light swapped.
fn qr_inverted(data: &str) -> String {
    QrCode::new(data.as_bytes())
        .expect("encodable")
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .build()
}

fn has_qr_glyphs(s: &str) -> bool {
    s.chars().any(|c| QR_GLYPHS.contains(&c))
}

// ---- device_messages: with verification_uri_complete ----

#[test]
fn complete_link_comes_first_then_plain_uri_with_code_then_qr() {
    let msgs = device_messages(&start(Some(COMPLETE)), QrMode::On);
    assert_eq!(msgs.len(), 3, "link, plain URI + code, QR: {msgs:?}");

    assert!(
        msgs[0].contains(COMPLETE),
        "first line is the prefilled link: {msgs:?}"
    );
    assert!(!has_qr_glyphs(&msgs[0]));

    assert!(
        msgs[1].contains(URI),
        "second line names the plain URI: {msgs:?}"
    );
    assert!(
        msgs[1].contains(CODE),
        "second line names the user code: {msgs:?}"
    );
    assert!(
        !msgs[1].contains(COMPLETE),
        "second line is the plain URI, not the prefilled one: {msgs:?}"
    );
    assert!(!has_qr_glyphs(&msgs[1]));

    assert_eq!(msgs[2], qr(COMPLETE), "QR of the prefilled link, Dense1x2");
}

#[test]
fn qr_on_is_one_multiline_message_of_half_blocks() {
    let msgs = device_messages(&start(Some(COMPLETE)), QrMode::On);
    let code = msgs.last().expect("a QR message");
    assert!(code.lines().count() > 10, "a whole QR code in one message");
    assert!(has_qr_glyphs(code));
    assert!(
        code.chars()
            .all(|c| c == ' ' || c == '\n' || QR_GLYPHS.contains(&c)),
        "only Dense1x2 glyphs, no ANSI or other decoration"
    );
    let widths: Vec<usize> = code.lines().map(|l| l.chars().count()).collect();
    assert!(
        widths.windows(2).all(|w| w[0] == w[1]),
        "every row has the same width: {widths:?}"
    );
}

#[test]
fn qr_invert_swaps_dark_and_light() {
    let msgs = device_messages(&start(Some(COMPLETE)), QrMode::Invert);
    assert_eq!(msgs.len(), 3, "{msgs:?}");
    assert!(msgs[0].contains(COMPLETE));
    assert!(msgs[1].contains(URI) && msgs[1].contains(CODE));
    assert_eq!(msgs[2], qr_inverted(COMPLETE));
    assert_ne!(
        msgs[2],
        qr(COMPLETE),
        "inverted differs from the plain rendering"
    );
}

#[test]
fn qr_off_has_no_qr_message() {
    let msgs = device_messages(&start(Some(COMPLETE)), QrMode::Off);
    assert_eq!(msgs.len(), 2, "link and plain URI + code only: {msgs:?}");
    assert!(msgs[0].contains(COMPLETE));
    assert!(msgs[1].contains(URI) && msgs[1].contains(CODE));
    assert!(msgs.iter().all(|m| !has_qr_glyphs(m)), "{msgs:?}");
}

#[test]
fn text_lines_are_single_lines() {
    for mode in [QrMode::On, QrMode::Off, QrMode::Invert] {
        for complete in [Some(COMPLETE), None] {
            let msgs = device_messages(&start(complete), mode);
            let text = if mode == QrMode::Off {
                &msgs[..]
            } else {
                &msgs[..msgs.len() - 1]
            };
            for line in text {
                assert!(!line.is_empty(), "{mode:?} {complete:?}: {msgs:?}");
                assert!(!line.contains('\n'), "{mode:?} {complete:?}: {line:?}");
            }
        }
    }
}

// ---- device_messages: without verification_uri_complete ----

#[test]
fn without_complete_uri_starts_with_plain_uri_and_code() {
    let msgs = device_messages(&start(None), QrMode::On);
    assert_eq!(msgs.len(), 2, "plain URI + code, then QR: {msgs:?}");
    assert!(msgs[0].contains(URI) && msgs[0].contains(CODE), "{msgs:?}");
    assert!(
        !msgs[0].contains("?code="),
        "no made-up prefilled link: {msgs:?}"
    );
    assert!(!msgs[0].contains("None"), "no Option debug text: {msgs:?}");
    assert_eq!(msgs[1], qr(URI), "QR falls back to the plain URI");
}

#[test]
fn without_complete_uri_inverted_qr_of_plain_uri() {
    let msgs = device_messages(&start(None), QrMode::Invert);
    assert_eq!(msgs.len(), 2, "{msgs:?}");
    assert!(msgs[0].contains(URI) && msgs[0].contains(CODE));
    assert_eq!(msgs[1], qr_inverted(URI));
}

#[test]
fn without_complete_uri_and_qr_off_is_one_line() {
    let msgs = device_messages(&start(None), QrMode::Off);
    assert_eq!(msgs.len(), 1, "{msgs:?}");
    assert!(msgs[0].contains(URI) && msgs[0].contains(CODE));
    assert!(!has_qr_glyphs(&msgs[0]));
}

#[test]
fn messages_never_include_debug_formatting() {
    for complete in [Some(COMPLETE), None] {
        for m in device_messages(&start(complete), QrMode::Off) {
            assert!(!m.contains("Some("), "{m:?}");
            assert!(!m.contains("None"), "{m:?}");
        }
    }
}

// ---- wait_prompt ----

#[test]
fn wait_prompt_enter_asks_to_press_enter() {
    assert_eq!(wait_prompt(WaitMode::Enter), Some(ENTER_PROMPT));
    assert_eq!(
        ENTER_PROMPT,
        "Press Enter once you've approved (q to cancel): "
    );
}

#[test]
fn wait_prompt_poll_has_no_prompt() {
    assert_eq!(wait_prompt(WaitMode::Poll), None);
}

#[test]
fn wait_prompt_auto_has_no_prompt() {
    // The caller resolves Auto with Config::wait_mode_for first.
    assert_eq!(wait_prompt(WaitMode::Auto), None);
}

// ---- is_cancel ----

#[test]
fn q_cancels_in_either_case() {
    assert!(is_cancel("q"));
    assert!(is_cancel("Q"));
}

#[test]
fn q_with_surrounding_whitespace_cancels() {
    assert!(is_cancel(" q"));
    assert!(is_cancel("q "));
    assert!(is_cancel("\tQ\n"));
    assert!(is_cancel("  q\r\n"));
}

#[test]
fn other_answers_do_not_cancel() {
    for answer in ["", " ", "\n", "y", "quit", "qq", "x q", "1", "Enter"] {
        assert!(!is_cancel(answer), "{answer:?}");
    }
}
