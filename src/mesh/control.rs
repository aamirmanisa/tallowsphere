//! Control plane: pause, resume, inject, stop, status.
//!
//! A mesh run is long-lived, so control has to be an API with recorded effects,
//! not a signal. `inject` in particular must be journalled with the wave it took
//! effect at — an injection that is not in the journal makes the run
//! unreplayable, which is the one property this design will not trade away.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

#[derive(Default)]
pub struct RunControl {
    paused: AtomicBool,
    stopped: AtomicBool,
    /// key -> (value, wave the injection becomes visible at)
    injections: Mutex<Vec<(String, String, usize)>>,
    counters: Mutex<HashMap<String, u64>>,
}

impl RunControl {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
    }

    pub fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// Make `key = value` visible from wave `effective_wave` onward. The wave is
    /// chosen by the caller and recorded, not inferred from a clock.
    pub fn inject(&self, key: &str, value: &str, effective_wave: usize) {
        self.injections
            .lock()
            .unwrap()
            .push((key.to_string(), value.to_string(), effective_wave));
    }

    /// Injections visible at `wave`, in insertion order.
    pub fn injections_for(&self, wave: usize) -> Vec<(String, String)> {
        self.injections
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, _, w)| *w <= wave)
            .map(|(k, v, _)| (k.clone(), v.clone()))
            .collect()
    }

    pub fn all_injections(&self) -> Vec<(String, String, usize)> {
        self.injections.lock().unwrap().clone()
    }

    pub fn bump(&self, counter: &str) {
        *self
            .counters
            .lock()
            .unwrap()
            .entry(counter.to_string())
            .or_insert(0) += 1;
    }

    pub fn counter(&self, name: &str) -> u64 {
        self.counters
            .lock()
            .unwrap()
            .get(name)
            .copied()
            .unwrap_or(0)
    }

    pub fn counters(&self) -> HashMap<String, u64> {
        self.counters.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pause_and_resume_are_visible() {
        let c = RunControl::new();
        assert!(!c.is_paused());
        c.pause();
        assert!(c.is_paused());
        c.resume();
        assert!(!c.is_paused());
    }

    #[test]
    fn an_injection_is_visible_only_from_its_wave() {
        let c = RunControl::new();
        c.inject("rate", "5", 2);
        assert!(c.injections_for(0).is_empty());
        assert!(c.injections_for(1).is_empty());
        assert_eq!(
            c.injections_for(2),
            vec![("rate".to_string(), "5".to_string())]
        );
        assert_eq!(c.injections_for(7).len(), 1, "stays visible afterwards");
    }

    #[test]
    fn injections_keep_insertion_order() {
        let c = RunControl::new();
        c.inject("a", "1", 0);
        c.inject("b", "2", 0);
        let got: Vec<String> = c.injections_for(0).into_iter().map(|(k, _)| k).collect();
        assert_eq!(got, vec!["a", "b"]);
    }

    #[test]
    fn counters_are_per_key() {
        let c = RunControl::new();
        c.bump("waves");
        c.bump("waves");
        c.bump("tasks");
        assert_eq!(c.counter("waves"), 2);
        assert_eq!(c.counter("tasks"), 1);
        assert_eq!(c.counter("missing"), 0);
    }
}
