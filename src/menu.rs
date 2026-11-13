//! The numbered method menu.
//!
//! Shows `1) <label>` lines via `Conv::info` in `cfg.methods` order, then asks
//! with `Conv::prompt_echo_on`. Answers are the item number (surrounding
//! whitespace ignored); an empty answer picks `cfg.default_method`.

use crate::args::{Config, Method};
use crate::error::Error;
use crate::pam::Conv;

/// Invalid answers allowed before giving up with [`Error::BadMenuInput`].
pub const MAX_ATTEMPTS: u32 = 3;

/// Asks the user which method to use. A config with a single method returns
/// it without any conversation.
///
/// # Errors
/// [`Error::BadMenuInput`] after [`MAX_ATTEMPTS`] invalid answers;
/// [`Error::Conv`] if the conversation fails.
pub fn choose(cfg: &Config, conv: &dyn Conv) -> Result<Method, Error> {
    if let [only] = cfg.methods[..] {
        return Ok(only);
    }
    for (n, &m) in (1..).zip(&cfg.methods) {
        conv.info(&format!("{n}) {}", cfg.label(m)))?;
    }
    let prompt = format!(
        "Choose a login method (Enter for {}): ",
        cfg.label(cfg.default_method)
    );
    for _ in 0..MAX_ATTEMPTS {
        let answer = conv.prompt_echo_on(&prompt)?;
        let answer = answer.trim();
        if answer.is_empty() {
            return Ok(cfg.default_method);
        }
        if let Some(&m) = answer
            .parse::<usize>()
            .ok()
            .and_then(|n| cfg.methods.get(n.wrapping_sub(1)))
        {
            return Ok(m);
        }
        conv.error_msg("Please answer with one of the numbers shown.")?;
    }
    Err(Error::BadMenuInput)
}

#[cfg(test)]
#[path = "tests/menu_tests.rs"]
mod tests;
