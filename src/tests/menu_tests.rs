#[allow(unused_imports)]
use super::*;

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use openidconnect::url::Url;

use crate::args::{DEFAULT_PASS_LABEL, DEFAULT_SSO_LABEL, Labels};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Ev {
    Info(String),
    ErrorMsg(String),
    Prompt(String),
}

/// A scripted conversation: answers are handed out in order; running out of
/// answers is a conversation failure. Any kind of call can be made to fail.
#[derive(Default)]
struct FakeConv {
    answers: RefCell<VecDeque<String>>,
    events: RefCell<Vec<Ev>>,
    fail_info: Cell<bool>,
    fail_error_msg: Cell<bool>,
    fail_prompt: Cell<bool>,
}

impl FakeConv {
    fn answering(answers: &[&str]) -> Self {
        let conv = Self::default();
        conv.answers
            .borrow_mut()
            .extend(answers.iter().map(|&a| a.to_owned()));
        conv
    }

    fn events(&self) -> Vec<Ev> {
        self.events.borrow().clone()
    }

    fn prompts(&self) -> usize {
        self.events()
            .iter()
            .filter(|e| matches!(e, Ev::Prompt(_)))
            .count()
    }

    fn infos(&self) -> Vec<String> {
        self.events()
            .into_iter()
            .filter_map(|e| match e {
                Ev::Info(s) => Some(s),
                _ => None,
            })
            .collect()
    }

    fn error_msgs(&self) -> usize {
        self.events()
            .iter()
            .filter(|e| matches!(e, Ev::ErrorMsg(_)))
            .count()
    }
}

impl Conv for FakeConv {
    fn info(&self, msg: &str) -> Result<(), Error> {
        self.events.borrow_mut().push(Ev::Info(msg.to_owned()));
        if self.fail_info.get() {
            Err(Error::Conv)
        } else {
            Ok(())
        }
    }

    fn error_msg(&self, msg: &str) -> Result<(), Error> {
        self.events.borrow_mut().push(Ev::ErrorMsg(msg.to_owned()));
        if self.fail_error_msg.get() {
            Err(Error::Conv)
        } else {
            Ok(())
        }
    }

    fn prompt_echo_on(&self, prompt: &str) -> Result<String, Error> {
        self.events.borrow_mut().push(Ev::Prompt(prompt.to_owned()));
        if self.fail_prompt.get() {
            return Err(Error::Conv);
        }
        self.answers.borrow_mut().pop_front().ok_or(Error::Conv)
    }
}

fn cfg() -> Config {
    Config::new(
        Url::parse("https://idp.example.test/application/o/login/").unwrap(),
        "login-sso",
    )
}

fn cfg_with(methods: &[Method], default: Method) -> Config {
    let mut c = cfg();
    c.methods = methods.to_vec();
    c.default_method = default;
    c
}

#[test]
fn max_attempts_is_three() {
    assert_eq!(MAX_ATTEMPTS, 3);
}

#[test]
fn shows_numbered_labels_in_methods_order_then_prompts() {
    let conv = FakeConv::answering(&["1"]);
    assert_eq!(choose(&cfg(), &conv), Ok(Method::Pass));
    let ev = conv.events();
    assert_eq!(ev.len(), 3, "{ev:?}");
    assert_eq!(ev[0], Ev::Info(format!("1) {DEFAULT_PASS_LABEL}")));
    assert_eq!(ev[1], Ev::Info(format!("2) {DEFAULT_SSO_LABEL}")));
    assert!(matches!(&ev[2], Ev::Prompt(p) if !p.is_empty()), "{ev:?}");
}

#[test]
fn custom_labels_and_reversed_order() {
    let mut c = cfg_with(&[Method::Sso, Method::Pass], Method::Sso);
    c.labels = Labels {
        pass: "Directory".into(),
        sso: "Authentik".into(),
    };
    let conv = FakeConv::answering(&["2"]);
    assert_eq!(choose(&c, &conv), Ok(Method::Pass));
    assert_eq!(conv.infos(), ["1) Authentik", "2) Directory"]);
}

#[test]
fn second_item_is_sso() {
    let conv = FakeConv::answering(&["2"]);
    assert_eq!(choose(&cfg(), &conv), Ok(Method::Sso));
    assert_eq!(conv.prompts(), 1);
    assert_eq!(conv.error_msgs(), 0);
}

#[test]
fn surrounding_whitespace_is_ignored() {
    let conv = FakeConv::answering(&["  2 \t"]);
    assert_eq!(choose(&cfg(), &conv), Ok(Method::Sso));
    let conv = FakeConv::answering(&[" 1\n"]);
    assert_eq!(choose(&cfg(), &conv), Ok(Method::Pass));
}

#[test]
fn empty_answer_picks_the_default() {
    let c = cfg_with(&[Method::Pass, Method::Sso], Method::Sso);
    let conv = FakeConv::answering(&[""]);
    assert_eq!(choose(&c, &conv), Ok(Method::Sso));

    let c = cfg_with(&[Method::Pass, Method::Sso], Method::Pass);
    let conv = FakeConv::answering(&[""]);
    assert_eq!(choose(&c, &conv), Ok(Method::Pass));
}

#[test]
fn whitespace_only_answer_picks_the_default() {
    let c = cfg_with(&[Method::Sso, Method::Pass], Method::Pass);
    let conv = FakeConv::answering(&["   "]);
    assert_eq!(choose(&c, &conv), Ok(Method::Pass));
}

#[test]
fn single_method_needs_no_conversation() {
    for m in [Method::Pass, Method::Sso] {
        let c = cfg_with(&[m], m);
        let conv = FakeConv::default();
        conv.fail_info.set(true);
        conv.fail_prompt.set(true);
        conv.fail_error_msg.set(true);
        assert_eq!(choose(&c, &conv), Ok(m));
        assert!(conv.events().is_empty(), "{:?}", conv.events());
    }
}

#[test]
fn invalid_answers_are_retried_with_an_error_message() {
    let conv = FakeConv::answering(&["x", "9", "2"]);
    assert_eq!(choose(&cfg(), &conv), Ok(Method::Sso));
    assert_eq!(conv.prompts(), 3);
    assert_eq!(conv.error_msgs(), 2);
}

#[test]
fn three_invalid_answers_give_bad_menu_input() {
    let conv = FakeConv::answering(&["0", "3", "sso", "1"]);
    assert_eq!(choose(&cfg(), &conv), Err(Error::BadMenuInput));
    assert_eq!(conv.prompts(), 3, "exactly MAX_ATTEMPTS prompts");
    assert_eq!(
        conv.answers.borrow().len(),
        1,
        "the fourth answer is never asked for"
    );
}

#[test]
fn out_of_range_and_non_numeric_answers_are_invalid() {
    for bad in [
        "0",
        "3",
        "-1",
        "1.0",
        "one",
        "q",
        "12",
        "99999999999999999999",
    ] {
        let conv = FakeConv::answering(&[bad, bad, bad]);
        assert_eq!(choose(&cfg(), &conv), Err(Error::BadMenuInput), "{bad:?}");
    }
}

#[test]
fn two_entries_only_accept_one_and_two() {
    let c = cfg_with(&[Method::Sso, Method::Pass], Method::Sso);
    let conv = FakeConv::answering(&["3", "1"]);
    assert_eq!(choose(&c, &conv), Ok(Method::Sso));
}

#[test]
fn info_failure_is_conv_error() {
    let conv = FakeConv::answering(&["1"]);
    conv.fail_info.set(true);
    assert_eq!(choose(&cfg(), &conv), Err(Error::Conv));
    assert_eq!(conv.prompts(), 0, "no prompt after a failed info");
}

#[test]
fn prompt_failure_is_conv_error() {
    let conv = FakeConv::answering(&["1"]);
    conv.fail_prompt.set(true);
    assert_eq!(choose(&cfg(), &conv), Err(Error::Conv));
    assert_eq!(conv.prompts(), 1, "a failed prompt is not retried");
}

#[test]
fn error_msg_failure_is_conv_error() {
    let conv = FakeConv::answering(&["x", "1"]);
    conv.fail_error_msg.set(true);
    assert_eq!(choose(&cfg(), &conv), Err(Error::Conv));
    assert_eq!(conv.prompts(), 1);
}

#[test]
fn conv_failure_after_an_invalid_answer() {
    // The second prompt fails (no answer left): Conv, not BadMenuInput.
    let conv = FakeConv::answering(&["x"]);
    assert_eq!(choose(&cfg(), &conv), Err(Error::Conv));
}
