//! Text shown during the device flow.

use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;

use crate::args::{QrMode, WaitMode};
use crate::oidc::DeviceStart;

/// The prompt shown in [`WaitMode::Enter`].
pub const ENTER_PROMPT: &str = "Press Enter once you've approved (q to cancel): ";

/// The info lines for a started device flow, in order: the prefilled link
/// (`verification_uri_complete`, if any), the plain URI with the user code,
/// then (unless [`QrMode::Off`]) the QR code of the prefilled link (or of the
/// plain URI), rendered with `qrcode`'s `unicode::Dense1x2` as one multi-line
/// string. [`QrMode::Invert`] swaps dark and light. Data too long for a QR
/// code gets no QR message.
#[must_use]
pub fn device_messages(start: &DeviceStart, qr: QrMode) -> Vec<String> {
    let plain = format!(
        "go to {} and enter the code {}",
        start.verification_uri, start.user_code
    );
    let mut msgs = Vec::with_capacity(3);
    let link = if let Some(complete) = &start.verification_uri_complete {
        msgs.push(format!("To sign in, open {complete}"));
        msgs.push(format!("Or {plain}"));
        complete
    } else {
        msgs.push(format!("To sign in, {plain}"));
        &start.verification_uri
    };
    let colors = match qr {
        QrMode::Off => None,
        QrMode::On => Some((Dense1x2::Dark, Dense1x2::Light)),
        QrMode::Invert => Some((Dense1x2::Light, Dense1x2::Dark)),
    };
    if let Some((dark, light)) = colors {
        msgs.extend(QrCode::new(link.as_bytes()).ok().map(|code| {
            code.render::<Dense1x2>()
                .dark_color(dark)
                .light_color(light)
                .build()
        }));
    }
    msgs
}

/// The prompt to show before polling: `Some(ENTER_PROMPT)` for
/// [`WaitMode::Enter`], `None` otherwise (the caller resolves `Auto` first via
/// `Config::wait_mode_for`).
#[must_use]
pub fn wait_prompt(mode: WaitMode) -> Option<&'static str> {
    (mode == WaitMode::Enter).then_some(ENTER_PROMPT)
}

/// Whether an answer to [`ENTER_PROMPT`] cancels (`q` or `Q`, surrounding whitespace ignored).
#[must_use]
pub fn is_cancel(answer: &str) -> bool {
    answer.trim().eq_ignore_ascii_case("q")
}

#[cfg(test)]
#[path = "tests/prompt_tests.rs"]
mod tests;
