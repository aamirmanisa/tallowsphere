//! Clearness gate — question-only review workflow + fail-closed dissemination
//! check (tasks B2.1.1–B2.1.3, frozen interface §5).
//!
//! O4 "clearness gate": before sensitive material is disseminated, a panel of
//! at least two reviewers interrogates it. The workflow is **question-only**:
//! reviewers may submit *questions*, never statements, opinions, or
//! assessments. A separate **clerk** drives the session — [`ClearnessSession`]
//! is the clerk's ledger. The clerk records each reviewer's question
//! ([`ClearnessSession::ask`], attributed to a listed reviewer) and records
//! the answers as they land ([`ClearnessSession::answer`]). Reviewers never
//! write to the session themselves, and what the clerk may accept from them is
//! constrained by the question-only rule below.
//!
//! # The question-only rule (B2.1.1)
//!
//! [`ClearnessSession::ask`] accepts a submission only when its *trimmed* text
//! ends with `?`; anything else is refused with
//! [`ClearnessError::NotAQuestion`]. This is the point of the exercise: a
//! statement or opinion smuggles an assessment into the record, while a
//! question forces the material to answer for itself. There is deliberately no
//! "comment" or "note" channel.
//!
//! # Fail-closed dissemination (B2.1.3)
//!
//! [`ClearnessSession::can_disseminate`] returns `Ok(())` only when *both*
//! hold:
//!
//! 1. **Participation quorum** — every reviewer listed at open time asked at
//!    least one question; the first silent reviewer in listed order is
//!    reported ([`ClearnessError::NoQuestionFrom`]).
//! 2. **No open questions** — every question recorded has been answered;
//!    otherwise [`ClearnessError::OpenQuestions`] carries how many remain.
//!
//! Everything else keeps the gate closed. There is no override, no quorum
//! relaxation, and no credit for partial review — when in doubt, dissemination
//! is refused. Callers wiring this as a required release step (B2.1.2 — a
//! separate integration task, out of this module's scope) must treat any
//! `Err`, and any inability to run the check at all, as denial.
//!
//! # Documented rules (spec silent where noted; conservative reading)
//!
//! * **Open validation order**: reviewer count first
//!   ([`ClearnessError::TooFewReviewers`] for fewer than 2), then per-name
//!   emptiness, then duplicates — both reported as
//!   [`ClearnessError::BadInput`] with the reason name.
//! * **Reviewer names are trim-normalised** at open time (surrounding
//!   whitespace stripped, case preserved and compared case-sensitively) and
//!   stored in listed order. Listed order matters: it selects *which* silent
//!   reviewer [`ClearnessSession::can_disseminate`] names first.
//!   Normalisation is also applied to the `reviewer` argument of
//!   [`ClearnessSession::ask`], and questions are attributed to the stored
//!   (normalised) name, so a question's `asked_by` always equals a listed
//!   reviewer.
//! * **`ask` check order**: empty reviewer (`BadInput("reviewer")`), empty
//!   text (`BadInput("text")`), membership ([`ClearnessError::UnknownReviewer`]),
//!   then the question-only shape check ([`ClearnessError::NotAQuestion`]).
//!   An empty submission is malformed *input*, not a "statement", so it is
//!   refused as such — whitespace-only text is never silently accepted and
//!   never counts as the reviewer's question.
//! * **`answer` check order** (as listed in the frozen spec): unknown id
//!   ([`ClearnessError::UnknownQuestion`]), then empty text
//!   (`BadInput("text")`), then already answered
//!   ([`ClearnessError::AlreadyAnswered`]). A question once answered is never
//!   re-opened or re-written.
//! * **Stored text is exact**: question and answer text are kept verbatim
//!   (only *validated* on the trimmed form). Acceptance of a question is on
//!   the trimmed form, so trailing whitespace after the `?` is tolerated.
//! * **Ids** are `q-<seq:03>`, seq starting at 1, one per question asked;
//!   questions are never removed, so ids are stable and unique per session.
//!   No clocks anywhere: the whole workflow is a pure function of the call
//!   sequence, which is what makes the drill (B2.1.3) reproducible.
//! * [`ClearnessSession`] is **not** `serde` — the frozen spec annotates only
//!   [`Question`] and [`ClearnessError`]; the session is live runtime state
//!   owned by the clerk. [`ClearnessError`] derives `Serialize` but not
//!   `Deserialize`: its `BadInput(&'static str)` payload cannot be
//!   deserialized into a `'static` lifetime. This mirrors the in-repo
//!   precedent (`vouching::VouchError`, `gap_register`, `link_chain`,
//!   `decoy_flags`, `requirements`).

use serde::{Deserialize, Serialize};
use std::fmt;

/// One question in a clearness session, with its answer (once recorded by the
/// clerk). Question ids are `q-<seq:03>`; `asked_by` is the stored
/// (trim-normalised) name of a listed reviewer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Question {
    /// Deterministic id, `q-<seq:03>` (seq from 1, per session).
    pub id: String,
    /// The listed reviewer this question belongs to.
    pub asked_by: String,
    /// Question text, stored verbatim (accepted only if its trimmed form
    /// ends with `?`).
    pub text: String,
    /// The recorded answer; `None` while the question is still open.
    pub answer: Option<String>,
}

/// A clerk-driven, question-only review session.
///
/// Created with at least two reviewers ([`ClearnessSession::open`]); the clerk
/// records reviewer questions ([`ClearnessSession::ask`]) and their answers
/// ([`ClearnessSession::answer`]). Dissemination may only proceed once every
/// listed reviewer has asked at least one question and every question has been
/// answered ([`ClearnessSession::can_disseminate`], fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearnessSession {
    reviewers: Vec<String>,
    questions: Vec<Question>,
}

impl ClearnessSession {
    /// Open a session for `reviewers` (listed order is preserved and is
    /// significant for [`ClearnessSession::can_disseminate`]).
    ///
    /// Fewer than two reviewers ⇒ [`ClearnessError::TooFewReviewers`]; an
    /// empty/whitespace-only name ⇒ `BadInput("reviewer name")`; a duplicate
    /// name (after trimming) ⇒ `BadInput("duplicate reviewer")`.
    pub fn open(reviewers: Vec<String>) -> Result<ClearnessSession, ClearnessError> {
        if reviewers.len() < 2 {
            return Err(ClearnessError::TooFewReviewers);
        }
        let mut names: Vec<String> = Vec::with_capacity(reviewers.len());
        for reviewer in reviewers {
            let name = reviewer.trim();
            if name.is_empty() {
                return Err(ClearnessError::BadInput("reviewer name"));
            }
            if names.iter().any(|seen| seen == name) {
                return Err(ClearnessError::BadInput("duplicate reviewer"));
            }
            names.push(name.to_string());
        }
        Ok(ClearnessSession {
            reviewers: names,
            questions: Vec::new(),
        })
    }

    /// Record a question from a listed reviewer. The clerk accepts only
    /// questions: the trimmed `text` must end with `?`
    /// ([`ClearnessError::NotAQuestion`] otherwise).
    ///
    /// Errors, in order: empty reviewer ⇒ `BadInput("reviewer")`; empty text
    /// ⇒ `BadInput("text")`; reviewer not listed ⇒
    /// [`ClearnessError::UnknownReviewer`]; statement/opinion ⇒
    /// [`ClearnessError::NotAQuestion`].
    pub fn ask(&mut self, reviewer: &str, text: &str) -> Result<&Question, ClearnessError> {
        let name = reviewer.trim();
        if name.is_empty() {
            return Err(ClearnessError::BadInput("reviewer"));
        }
        if text.trim().is_empty() {
            return Err(ClearnessError::BadInput("text"));
        }
        let idx = self
            .reviewers
            .iter()
            .position(|listed| listed == name)
            .ok_or(ClearnessError::UnknownReviewer)?;
        if !text.trim().ends_with('?') {
            return Err(ClearnessError::NotAQuestion);
        }
        let id = format!("q-{:03}", self.questions.len() + 1);
        self.questions.push(Question {
            id,
            asked_by: self.reviewers[idx].clone(),
            text: text.to_string(),
            answer: None,
        });
        Ok(self.questions.last().expect("question was just pushed"))
    }

    /// Record the answer to question `qid`. Answers are recorded once and
    /// never rewritten.
    ///
    /// Errors, in order: unknown id ⇒ [`ClearnessError::UnknownQuestion`];
    /// empty text ⇒ `BadInput("text")`; already answered ⇒
    /// [`ClearnessError::AlreadyAnswered`].
    pub fn answer(&mut self, qid: &str, text: &str) -> Result<(), ClearnessError> {
        let question = self
            .questions
            .iter_mut()
            .find(|q| q.id == qid)
            .ok_or(ClearnessError::UnknownQuestion)?;
        if text.trim().is_empty() {
            return Err(ClearnessError::BadInput("text"));
        }
        if question.answer.is_some() {
            return Err(ClearnessError::AlreadyAnswered);
        }
        question.answer = Some(text.to_string());
        Ok(())
    }

    /// Fail-closed dissemination check. `Ok(())` only when *every* listed
    /// reviewer has asked at least one question (else
    /// [`ClearnessError::NoQuestionFrom`], first missing reviewer in listed
    /// order) **and** every question has been answered (else
    /// [`ClearnessError::OpenQuestions`] with the count). Any other state —
    /// including a fresh session — keeps the gate closed.
    pub fn can_disseminate(&self) -> Result<(), ClearnessError> {
        for reviewer in &self.reviewers {
            if !self.questions.iter().any(|q| q.asked_by == *reviewer) {
                return Err(ClearnessError::NoQuestionFrom(reviewer.clone()));
            }
        }
        let open = self.questions.iter().filter(|q| q.answer.is_none()).count();
        if open > 0 {
            return Err(ClearnessError::OpenQuestions(open));
        }
        Ok(())
    }

    /// Deterministic one-line status: reviewer count, question count, open
    /// (unanswered) question count. No clocks, no hidden state — calling it
    /// twice on an unchanged session returns the identical string.
    pub fn status_line(&self) -> String {
        let open = self.questions.iter().filter(|q| q.answer.is_none()).count();
        format!(
            "clearness: reviewers={} questions={} open={}",
            self.reviewers.len(),
            self.questions.len(),
            open
        )
    }
}

/// Errors from clearness-gate operations.
///
/// `Serialize` is derived; `Deserialize` is not — the `BadInput(&'static str)`
/// payload cannot be deserialized into a `'static` lifetime. This mirrors the
/// in-repo precedent (`vouching::VouchError` and siblings `gap_register` /
/// `link_chain` / `decoy_flags` / `requirements`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearnessError {
    /// Fewer than two reviewers were listed at open time.
    TooFewReviewers,
    /// A required input was empty or otherwise malformed; carries the
    /// field/reason name (`"reviewer"`, `"reviewer name"`, `"text"`,
    /// `"duplicate reviewer"`).
    BadInput(&'static str),
    /// The reviewer is not on this session's listed panel.
    UnknownReviewer,
    /// The submission is not a question (trimmed text does not end with `?`).
    /// Reviewers may never submit statements or opinions.
    NotAQuestion,
    /// No question with the given id exists on this session.
    UnknownQuestion,
    /// The question already has a recorded answer; answers are write-once.
    AlreadyAnswered,
    /// Participation quorum not met: this listed reviewer has asked no
    /// question (first such reviewer in listed order).
    NoQuestionFrom(String),
    /// This many questions are still unanswered.
    OpenQuestions(usize),
}

impl fmt::Display for ClearnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClearnessError::TooFewReviewers => {
                write!(f, "clearness gate requires at least 2 reviewers")
            }
            ClearnessError::BadInput(reason) => write!(f, "invalid input: {reason}"),
            ClearnessError::UnknownReviewer => {
                write!(f, "reviewer is not listed on this session")
            }
            ClearnessError::NotAQuestion => {
                write!(f, "question-only: text must end with '?'")
            }
            ClearnessError::UnknownQuestion => write!(f, "unknown question id"),
            ClearnessError::AlreadyAnswered => write!(f, "question already answered"),
            ClearnessError::NoQuestionFrom(reviewer) => {
                write!(f, "no question from reviewer: {reviewer}")
            }
            ClearnessError::OpenQuestions(n) => write!(f, "open questions: {n}"),
        }
    }
}

impl std::error::Error for ClearnessError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_reviewers() -> ClearnessSession {
        ClearnessSession::open(vec!["alice".to_string(), "bob".to_string()]).unwrap()
    }

    // --- B2.1.3 drill: happy path -----------------------------------------

    #[test]
    fn happy_path_quorum_asks_answers_disseminate_ok() {
        let mut s = two_reviewers();
        let q1 = s.ask("alice", "What evidence supports the figure?").unwrap();
        assert_eq!((q1.id.as_str(), q1.asked_by.as_str(), q1.answer.is_none()), ("q-001", "alice", true));
        s.ask("bob", "Which annex covers the retraction?").unwrap();
        // both asked, both answers still open → closed
        assert_eq!(s.can_disseminate(), Err(ClearnessError::OpenQuestions(2)));
        s.answer("q-001", "Annex B, table 3.").unwrap();
        assert_eq!(s.can_disseminate(), Err(ClearnessError::OpenQuestions(1)));
        s.answer("q-002", "Annex D.").unwrap();
        assert_eq!(s.can_disseminate(), Ok(()));
    }

    // --- open() validation -------------------------------------------------

    #[test]
    fn open_requires_at_least_two_reviewers() {
        assert_eq!(ClearnessSession::open(vec![]), Err(ClearnessError::TooFewReviewers));
        assert_eq!(
            ClearnessSession::open(vec!["alice".to_string()]),
            Err(ClearnessError::TooFewReviewers)
        );
        // the count check precedes name validation (documented order)
        assert_eq!(
            ClearnessSession::open(vec!["".to_string()]),
            Err(ClearnessError::TooFewReviewers)
        );
        assert_eq!(
            ClearnessSession::open(vec!["   ".to_string()]),
            Err(ClearnessError::TooFewReviewers)
        );
    }

    #[test]
    fn open_rejects_empty_and_duplicate_reviewer_names() {
        assert_eq!(
            ClearnessSession::open(vec!["alice".to_string(), "  ".to_string()]),
            Err(ClearnessError::BadInput("reviewer name"))
        );
        assert_eq!(
            ClearnessSession::open(vec!["alice".to_string(), "alice".to_string()]),
            Err(ClearnessError::BadInput("duplicate reviewer"))
        );
        // duplicates are detected on the trim-normalised form
        assert_eq!(
            ClearnessSession::open(vec![" alice ".to_string(), "alice".to_string()]),
            Err(ClearnessError::BadInput("duplicate reviewer"))
        );
        // stored names are normalised, in listed order
        let s = ClearnessSession::open(vec![" alice ".to_string(), "bob".to_string()]).unwrap();
        assert_eq!(s.reviewers, vec!["alice".to_string(), "bob".to_string()]);
    }

    // --- question-only rule -------------------------------------------------

    #[test]
    fn question_only_rule_rejects_statements_and_accepts_trimmed_questions() {
        let mut s = two_reviewers();
        assert_eq!(
            s.ask("alice", "I think this is fine."),
            Err(ClearnessError::NotAQuestion)
        );
        assert_eq!(s.ask("alice", "looks good"), Err(ClearnessError::NotAQuestion));
        // acceptance is on the trimmed form; text is stored verbatim
        let q = s.ask("alice", "  What evidence?  ").unwrap();
        assert_eq!(q.id, "q-001");
        assert_eq!(q.text, "  What evidence?  ");
        assert_eq!(q.asked_by, "alice");
        assert_eq!(q.answer, None);
        // rejected statements are never recorded
        assert_eq!(s.questions.len(), 1);
    }

    #[test]
    fn ask_check_order_and_empty_inputs() {
        let mut s = two_reviewers();
        assert_eq!(s.ask("", "Why?"), Err(ClearnessError::BadInput("reviewer")));
        assert_eq!(s.ask("   ", "Why?"), Err(ClearnessError::BadInput("reviewer")));
        assert_eq!(s.ask("alice", ""), Err(ClearnessError::BadInput("text")));
        assert_eq!(s.ask("alice", "   "), Err(ClearnessError::BadInput("text")));
        assert_eq!(s.ask("carol", "Why?"), Err(ClearnessError::UnknownReviewer));
        // membership lookup is normalised; attribution uses the stored name
        let q = s.ask("  alice ", "Why?").unwrap();
        assert_eq!(q.asked_by, "alice");
    }

    // --- fail-closed dissemination ------------------------------------------

    #[test]
    fn unanswered_questions_block_dissemination_with_count() {
        let mut s = two_reviewers();
        s.ask("alice", "Q1?").unwrap();
        s.ask("alice", "Q2?").unwrap();
        s.ask("bob", "Q3?").unwrap();
        assert_eq!(s.can_disseminate(), Err(ClearnessError::OpenQuestions(3)));
        s.answer("q-001", "A1").unwrap();
        s.answer("q-003", "A3").unwrap();
        assert_eq!(s.can_disseminate(), Err(ClearnessError::OpenQuestions(1)));
        s.answer("q-002", "A2").unwrap();
        assert_eq!(s.can_disseminate(), Ok(()));
    }

    #[test]
    fn silent_reviewer_reported_first_in_listed_order_before_open_questions() {
        // fresh session: the first listed reviewer is the first silent one
        let s = two_reviewers();
        assert_eq!(
            s.can_disseminate(),
            Err(ClearnessError::NoQuestionFrom("alice".to_string()))
        );

        // three reviewers: the *first* silent reviewer in listed order is named
        let mut s3 = ClearnessSession::open(vec![
            "alice".to_string(),
            "bob".to_string(),
            "carol".to_string(),
        ])
        .unwrap();
        s3.ask("alice", "From alice?").unwrap();
        s3.ask("carol", "From carol?").unwrap();
        assert_eq!(
            s3.can_disseminate(),
            Err(ClearnessError::NoQuestionFrom("bob".to_string()))
        );

        // participation quorum precedes the open-question count
        let mut s = two_reviewers();
        s.ask("alice", "Only question?").unwrap();
        assert_eq!(
            s.can_disseminate(),
            Err(ClearnessError::NoQuestionFrom("bob".to_string()))
        );
        s.answer("q-001", "Answered.").unwrap();
        assert_eq!(
            s.can_disseminate(),
            Err(ClearnessError::NoQuestionFrom("bob".to_string()))
        );
        s.ask("bob", "And this?").unwrap();
        assert_eq!(s.can_disseminate(), Err(ClearnessError::OpenQuestions(1)));
        s.answer("q-002", "Also answered.").unwrap();
        assert_eq!(s.can_disseminate(), Ok(()));
    }

    // --- answer() -----------------------------------------------------------

    #[test]
    fn answer_errors_unknown_empty_and_already_answered() {
        let mut s = two_reviewers();
        assert_eq!(s.answer("q-999", "A"), Err(ClearnessError::UnknownQuestion));
        s.ask("alice", "Q1?").unwrap();
        s.ask("bob", "Q2?").unwrap();
        assert_eq!(s.answer("q-001", "  "), Err(ClearnessError::BadInput("text")));
        s.answer("q-001", "First answer.").unwrap();
        // answer-twice: refused, and the first answer survives
        assert_eq!(
            s.answer("q-001", "Second answer."),
            Err(ClearnessError::AlreadyAnswered)
        );
        // spec-listed order: emptiness is checked before the already-answered state
        assert_eq!(s.answer("q-001", ""), Err(ClearnessError::BadInput("text")));
        assert_eq!(s.questions[0].answer.as_deref(), Some("First answer."));
    }

    // --- ids, status, determinism ------------------------------------------

    #[test]
    fn question_ids_are_sequential_and_stable() {
        let mut s = two_reviewers();
        let a = s.ask("alice", "One?").unwrap().id.clone();
        let b = s.ask("bob", "Two?").unwrap().id.clone();
        let c = s.ask("alice", "Three?").unwrap().id.clone();
        assert_eq!((a.as_str(), b.as_str(), c.as_str()), ("q-001", "q-002", "q-003"));
        // ids never shift when answers land
        s.answer("q-002", "A").unwrap();
        assert_eq!(
            s.questions.iter().map(|q| q.id.as_str()).collect::<Vec<_>>(),
            vec!["q-001", "q-002", "q-003"]
        );
    }

    #[test]
    fn status_line_is_deterministic_and_counted() {
        let mut s = two_reviewers();
        assert_eq!(s.status_line(), "clearness: reviewers=2 questions=0 open=0");
        s.ask("alice", "Q1?").unwrap();
        s.ask("bob", "Q2?").unwrap();
        assert_eq!(s.status_line(), "clearness: reviewers=2 questions=2 open=2");
        s.answer("q-001", "A").unwrap();
        let pinned = s.status_line();
        assert_eq!(pinned, "clearness: reviewers=2 questions=2 open=1");
        for _ in 0..5 {
            assert_eq!(s.status_line(), pinned);
        }
    }

    #[test]
    fn workflow_is_deterministic_across_replays() {
        let run = || {
            let mut s = two_reviewers();
            s.ask("alice", "Q1?").unwrap();
            s.ask("bob", "Q2?").unwrap();
            s.answer("q-002", "A2").unwrap();
            (s.questions.clone(), s.status_line(), s.can_disseminate())
        };
        let a = run();
        let b = run();
        assert_eq!(a, b);
    }

    // --- serde ---------------------------------------------------------------

    #[test]
    fn question_serde_roundtrip_and_exact_json() {
        let answered = Question {
            id: "q-001".to_string(),
            asked_by: "alice".to_string(),
            text: "What evidence?".to_string(),
            answer: Some("Annex B.".to_string()),
        };
        let open = Question {
            id: "q-002".to_string(),
            asked_by: "bob".to_string(),
            text: "Why?".to_string(),
            answer: None,
        };
        let aj = serde_json::to_string(&answered).unwrap();
        assert_eq!(
            aj,
            r#"{"id":"q-001","asked_by":"alice","text":"What evidence?","answer":"Annex B."}"#
        );
        assert_eq!(serde_json::from_str::<Question>(&aj).unwrap(), answered);
        let oj = serde_json::to_string(&open).unwrap();
        assert_eq!(oj, r#"{"id":"q-002","asked_by":"bob","text":"Why?","answer":null}"#);
        assert_eq!(serde_json::from_str::<Question>(&oj).unwrap(), open);

        // a session-built question serializes the same way
        let mut s = two_reviewers();
        s.ask("alice", "What evidence?").unwrap();
        s.answer("q-001", "Annex B.").unwrap();
        assert_eq!(serde_json::to_string(&s.questions[0]).unwrap(), aj);
    }

    #[test]
    fn clearness_error_serde_and_display_pins() {
        assert_eq!(
            serde_json::to_string(&ClearnessError::TooFewReviewers).unwrap(),
            "\"too_few_reviewers\""
        );
        assert_eq!(
            serde_json::to_string(&ClearnessError::BadInput("text")).unwrap(),
            r#"{"bad_input":"text"}"#
        );
        assert_eq!(
            serde_json::to_string(&ClearnessError::UnknownReviewer).unwrap(),
            "\"unknown_reviewer\""
        );
        assert_eq!(
            serde_json::to_string(&ClearnessError::NotAQuestion).unwrap(),
            "\"not_a_question\""
        );
        assert_eq!(
            serde_json::to_string(&ClearnessError::UnknownQuestion).unwrap(),
            "\"unknown_question\""
        );
        assert_eq!(
            serde_json::to_string(&ClearnessError::AlreadyAnswered).unwrap(),
            "\"already_answered\""
        );
        assert_eq!(
            serde_json::to_string(&ClearnessError::NoQuestionFrom("bob".to_string())).unwrap(),
            r#"{"no_question_from":"bob"}"#
        );
        assert_eq!(
            serde_json::to_string(&ClearnessError::OpenQuestions(3)).unwrap(),
            r#"{"open_questions":3}"#
        );

        assert_eq!(
            ClearnessError::TooFewReviewers.to_string(),
            "clearness gate requires at least 2 reviewers"
        );
        assert_eq!(ClearnessError::BadInput("text").to_string(), "invalid input: text");
        assert_eq!(
            ClearnessError::UnknownReviewer.to_string(),
            "reviewer is not listed on this session"
        );
        assert_eq!(
            ClearnessError::NotAQuestion.to_string(),
            "question-only: text must end with '?'"
        );
        assert_eq!(ClearnessError::UnknownQuestion.to_string(), "unknown question id");
        assert_eq!(ClearnessError::AlreadyAnswered.to_string(), "question already answered");
        assert_eq!(
            ClearnessError::NoQuestionFrom("bob".to_string()).to_string(),
            "no question from reviewer: bob"
        );
        assert_eq!(ClearnessError::OpenQuestions(2).to_string(), "open questions: 2");

        // usable as a std::error::Error
        let e: Box<dyn std::error::Error> = Box::new(ClearnessError::NotAQuestion);
        assert_eq!(e.to_string(), "question-only: text must end with '?'");
    }
}
