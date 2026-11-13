//! Text shown during the device flow.

use crate::args::{QrMode, WaitMode};
use crate::oidc::DeviceStart;

/// The prompt shown in [`WaitMode::Enter`].
pub const ENTER_PROMPT: &str = "Press Enter once you've approved (q to cancel): ";

/// The info lines for a started device flow, in order: the prefilled link
/// (`verification_uri_complete`, if any), the plain URI with the user code,
/// then (unless [`QrMode::Off`]) the QR code of the prefilled link (or of the
/// plain URI), rendered with `qrcode`'s `unicode::Dense1x2` as one multi-line
/// string. [`QrMode::Invert`] swaps dark and light.
#[must_use]
pub fn device_messages(_start: &DeviceStart, _qr: QrMode) -> Vec<String> {
    todo!()
}

/// The prompt to show before polling: `Some(ENTER_PROMPT)` for
/// [`WaitMode::Enter`], `None` otherwise (the caller resolves `Auto` first via
/// `Config::wait_mode_for`).
#[must_use]
pub fn wait_prompt(_mode: WaitMode) -> Option<&'static str> {
    todo!()
}

/// Whether an answer to [`ENTER_PROMPT`] cancels (`q` or `Q`, surrounding whitespace ignored).
#[must_use]
pub fn is_cancel(_answer: &str) -> bool {
    todo!()
}

#[cfg(test)]
#[path = "tests/prompt_tests.rs"]
mod tests;
