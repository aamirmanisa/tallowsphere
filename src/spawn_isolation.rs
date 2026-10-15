//! Cell spawn-tree with sibling isolation and blast-radius state visibility —
//! task B1.3.1 (sibling isolation + routing) and B1.3.3 (blast radius), batch
//! 10 §2 (AGT-102).
//!
//! A **cell** is the isolation unit a persona operates from: cells are spawned
//! as a tree (one parent, many children), and the tree — not a flat team — is
//! what enforces containment. This module is the *model* half of that
//! discipline: [`SpawnTree`] owns the deterministic spawn topology, answers
//! relationship queries ([`SpawnTree::relation`]), decides the routing channel
//! for a cross-cell interaction ([`SpawnTree::route`]) and enforces the
//! **blast-radius rule** for state reads ([`SpawnTree::state_visible_to`]).
//! It is deliberately self-contained — there are **no cross-imports**: the
//! liaison link below is a documented integration note, not a dependency.
//!
//! # Sibling isolation and routing (B1.3.1)
//! Cells relate along the tree axes:
//! - **self** — [`Relation::Self_`];
//! - **ancestor ↔ descendant** — [`Relation::ParentChild`] (covers any
//!   ancestor/descendant pair, not just direct parent/child, since the frozen
//!   relation vocabulary has no separate "grandparent" shape); `direction` is
//!   `Down` when the **second** argument sits below the first (the first is its
//!   ancestor) and `Up` when the second sits above (the first is its
//!   descendant);
//! - **siblings** — [`Relation::Siblings`]: two distinct nodes sharing the same
//!   *non-empty* parent. Nodes with `parent = None` (roots) are never siblings:
//!   there is no common parent to share;
//! - **cousins** — [`Relation::Cousins`]: any two (non-ancestor) nodes under
//!   different child-branches of a common ancestor — i.e. a lowest common
//!   ancestor exists and is neither of the two;
//! - **unrelated** — [`Relation::Unrelated`]: no common ancestor at all
//!   (including nodes in different roots — see the forest note below).
//!
//! Routing ([`SpawnTree::route`]): an interaction **along the lineage**
//! (ancestor ↔ descendant, either direction) may go [`Route::Direct`].
//! **Everything else** — siblings, cousins, unrelated cells — must go
//! [`Route::ViaLiaison`]: a cross-cell handoff outside the lineage is only
//! legal through the logged liaison path (frozen rule; the liaison module
//! `src/liaison.rs` §3 is the log half of this channel — integration note, no
//! cross-import). A cell never silently reaches sideways.
//!
//! # Blast-radius rule (B1.3.3)
//! **A cell may read ONLY its own subtree (itself + its descendants).**
//! [`SpawnTree::state_visible_to`] returns `Ok(())` for `owner == viewer` or
//! `owner` a descendant of `viewer`, and `Err(IsolationError::NotAuthorized {
//! viewer, owner })` for anything else — siblings, cousins, ancestors
//! (visibility is **downward only**: a parent may read its child's state, but
//! the child may not read the parent's) and unrelated cells. The error message
//! names both cells. Consequence: if one cell is compromised, the readable
//! state is exactly that cell's subtree — the damage cannot walk upward or
//! sideways through the tree.
//!
//! # Pinned interpretations (argued in the batch report AGT-102.md)
//! 1. `route(x, x)` is [`Route::Direct`]: no cell boundary is crossed, so it is
//!    not a cross-cell handoff (the literal "everything else" reading would
//!    force a liaison entry for a no-op). All *distinct-cell* non-lineage pairs
//!    are `ViaLiaison`.
//! 2. Error precedence in [`SpawnTree::spawn`]: `EmptyId` → `DuplicateCell` →
//!    `UnknownCell` (empty-id and duplicate checks do not require a known
//!    parent; pinned by test).
//! 3. The frozen error vocabulary has no "multiple roots" variant, so the
//!    model is technically a **forest**: calling [`SpawnTree::root`] twice with
//!    different ids is allowed, and nodes under different roots are
//!    [`Relation::Unrelated`]. The first root is the nominal tree root; callers
//!    wanting exactly one root should simply not call `root` again.
//! 4. Every operation on an unknown id returns `UnknownCell` (including
//!    `relation`/`route`/`state_visible_to`/`siblings`).
//!
//! # Determinism
//! All outputs are pure functions of the stored cells: no clock, no randomness.
//! Sibling listings are sorted by id. Serde round-trips the tree and every
//! vocabulary type (see tests).


use std::fmt;

use serde::{Deserialize, Serialize};

/// One cell in the spawn tree.
///
/// `parent = None` marks a root cell (see the forest note in the module docs);
/// `persona` is the optional persona/cell flavor this cell runs under
/// (`src/persona.rs` vocabulary — that module is NOT edited here).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cell {
    /// Unique cell id (empty ids are rejected at spawn time).
    pub id: String,
    /// Parent cell id, or `None` for a root.
    pub parent: Option<String>,
    /// Optional persona id this cell operates as.
    pub persona: Option<String>,
}

/// Direction qualifier of a [`Relation::ParentChild`] relation: describes where
/// the **second** argument (`b`) sits relative to the first (`a`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Direction {
    /// `b` is a descendant of `a` (b sits below a).
    Down,
    /// `b` is an ancestor of `a` (b sits above a).
    Up,
}

/// How two cells in a [`SpawnTree`] relate. See the module docs for the exact
/// pins; `Self_` is the self-relation of a node with itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Relation {
    /// `a == b`.
    Self_,
    /// `b` is an ancestor or descendant of `a` (any depth; see [`Direction`]).
    ParentChild { direction: Direction },
    /// Distinct nodes sharing one *non-empty* parent.
    Siblings,
    /// Nodes under different child-branches of a common ancestor.
    Cousins,
    /// No common ancestor (includes nodes under different roots).
    Unrelated,
}

/// Routing decision for an interaction from one cell to another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Route {
    /// In-lineage (ancestor ↔ descendant): the interaction may go directly.
    Direct,
    /// Everything else (siblings, cousins, unrelated): the interaction must go
    /// through the logged liaison path — see `src/liaison.rs` §3 (integration
    /// note; no cross-import).
    ViaLiaison,
}

/// Why a spawn-tree operation was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsolationError {
    /// A cell id was empty.
    EmptyId,
    /// The id already exists in the tree.
    DuplicateCell,
    /// The referenced id is not present in the tree.
    UnknownCell,
    /// Blast-radius denial: `viewer` is not allowed to read `owner`'s state
    /// (owner is neither viewer nor a descendant of viewer).
    NotAuthorized { viewer: String, owner: String },
}

impl fmt::Display for IsolationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IsolationError::EmptyId => write!(f, "cell id must not be empty"),
            IsolationError::DuplicateCell => {
                write!(f, "cell id already exists in the spawn tree")
            }
            IsolationError::UnknownCell => {
                write!(f, "cell id is not present in the spawn tree")
            }
            IsolationError::NotAuthorized { viewer, owner } => write!(
                f,
                "cell `{viewer}` is not authorized to read state of `{owner}` \
                 (blast-radius rule: a cell may read only its own subtree)"
            ),
        }
    }
}

impl std::error::Error for IsolationError {}

/// Deterministic cell spawn-tree — B1.3.1 (routing/sibling isolation) and
/// B1.3.3 (blast-radius state visibility).
///
/// Cells are stored in spawn order (roots and children), which fixes every
/// iteration in this module; `siblings` (the only list-returning operation)
/// sorts by id explicitly.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnTree {
    cells: Vec<Cell>,
}

impl SpawnTree {
    /// Empty tree.
    pub fn new() -> Self {
        SpawnTree { cells: Vec::new() }
    }

    /// Add a root cell (`parent = None`).
    ///
    /// Empty id ⇒ [`IsolationError::EmptyId`]; id already present ⇒
    /// [`IsolationError::DuplicateCell`]. See the forest note in the module
    /// docs for repeated `root` calls with distinct ids.
    pub fn root(&mut self, id: &str, persona: Option<&str>) -> Result<(), IsolationError> {
        if id.is_empty() {
            return Err(IsolationError::EmptyId);
        }
        if self.exists(id) {
            return Err(IsolationError::DuplicateCell);
        }
        self.cells.push(Cell {
            id: id.to_string(),
            parent: None,
            persona: persona.map(str::to_string),
        });
        Ok(())
    }

    /// Spawn a child cell under `parent`.
    ///
    /// Error precedence (pinned): empty id ⇒ [`IsolationError::EmptyId`];
    /// id already present ⇒ [`IsolationError::DuplicateCell`]; `parent` not in
    /// the tree ⇒ [`IsolationError::UnknownCell`]. Nothing is stored on error.
    pub fn spawn(
        &mut self,
        parent: &str,
        id: &str,
        persona: Option<&str>,
    ) -> Result<(), IsolationError> {
        if id.is_empty() {
            return Err(IsolationError::EmptyId);
        }
        if self.exists(id) {
            return Err(IsolationError::DuplicateCell);
        }
        if !self.exists(parent) {
            return Err(IsolationError::UnknownCell);
        }
        self.cells.push(Cell {
            id: id.to_string(),
            parent: Some(parent.to_string()),
            persona: persona.map(str::to_string),
        });
        Ok(())
    }

    /// Borrow a cell by id (`None` when absent).
    pub fn cell(&self, id: &str) -> Option<&Cell> {
        self.cells.iter().find(|c| c.id == id)
    }

    /// Number of cells in the tree.
    pub fn len(&self) -> usize {
        self.cells.len()
    }

    /// True when the tree has no cells.
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    /// How `b` relates to `a`. Both ids must exist ⇒ else `UnknownCell`.
    ///
    /// Pins (see module docs): ancestor/descendant at any depth is
    /// [`Relation::ParentChild`] with [`Direction::Down`] when `b` is below `a`
    /// and [`Direction::Up`] when `b` is above `a`; siblings share a *non-empty*
    /// parent; cousins share a lowest common ancestor that is neither node;
    /// otherwise unrelated.
    pub fn relation(&self, a: &str, b: &str) -> Result<Relation, IsolationError> {
        let a_cell = self.cell(a).ok_or(IsolationError::UnknownCell)?;
        let b_cell = self.cell(b).ok_or(IsolationError::UnknownCell)?;
        if a == b {
            return Ok(Relation::Self_);
        }
        if self.is_ancestor(a, b) {
            return Ok(Relation::ParentChild {
                direction: Direction::Down,
            });
        }
        if self.is_ancestor(b, a) {
            return Ok(Relation::ParentChild {
                direction: Direction::Up,
            });
        }
        if a_cell.parent.is_some() && a_cell.parent == b_cell.parent {
            return Ok(Relation::Siblings);
        }
        if self.lowest_common_ancestor(a, b).is_some() {
            return Ok(Relation::Cousins);
        }
        Ok(Relation::Unrelated)
    }

    /// Routing channel for an interaction from `from` to `to`. Both ids must
    /// exist ⇒ else `UnknownCell`.
    ///
    /// Ancestors ↔ descendants (either direction) and the self-route are
    /// [`Route::Direct`]; every distinct-cell pair off the lineage (siblings,
    /// cousins, unrelated) is [`Route::ViaLiaison`] — the cross-cell handoff
    /// rule, logged via `src/liaison.rs` §3.
    pub fn route(&self, from: &str, to: &str) -> Result<Route, IsolationError> {
        if !self.exists(from) || !self.exists(to) {
            return Err(IsolationError::UnknownCell);
        }
        if from == to {
            // Pinned interpretation #1: no boundary is crossed; not a handoff.
            return Ok(Route::Direct);
        }
        if self.is_ancestor(from, to) || self.is_ancestor(to, from) {
            return Ok(Route::Direct);
        }
        Ok(Route::ViaLiaison)
    }

    /// **Blast-radius rule (B1.3.3):** `viewer` may read `owner`'s state only
    /// when `owner` is `viewer` itself or a descendant of `viewer`.
    ///
    /// Anything else — sibling, cousin, ancestor, unrelated — ⇒
    /// `Err(NotAuthorized { viewer, owner })` (message names both cells).
    /// Both ids must exist ⇒ else `UnknownCell`.
    pub fn state_visible_to(&self, viewer: &str, owner: &str) -> Result<(), IsolationError> {
        if !self.exists(viewer) || !self.exists(owner) {
            return Err(IsolationError::UnknownCell);
        }
        if owner == viewer || self.is_ancestor(viewer, owner) {
            return Ok(());
        }
        Err(IsolationError::NotAuthorized {
            viewer: viewer.to_string(),
            owner: owner.to_string(),
        })
    }

    /// Siblings of `id` (same non-empty parent, excluding `id`), **sorted by
    /// id** for deterministic output. A root has no siblings ⇒ empty vec;
    /// unknown id ⇒ `UnknownCell`.
    pub fn siblings(&self, id: &str) -> Result<Vec<&Cell>, IsolationError> {
        let cell = self.cell(id).ok_or(IsolationError::UnknownCell)?;
        let Some(parent) = cell.parent.as_deref() else {
            return Ok(Vec::new());
        };
        let mut out: Vec<&Cell> = self
            .cells
            .iter()
            .filter(|c| c.id != id && c.parent.as_deref() == Some(parent))
            .collect();
        out.sort_by(|x, y| x.id.cmp(&y.id));
        Ok(out)
    }

    // ---- internals ----------------------------------------------------

    fn exists(&self, id: &str) -> bool {
        self.cells.iter().any(|c| c.id == id)
    }

    /// Ancestors of `id`, nearest first (parent, grandparent, …). `id` itself
    /// is excluded. The walk is bounded by the cell count; the parent links are
    /// acyclic **by construction** (a parent must exist before its child, and
    /// roots have no parent), so no cycle guard beyond the bound is needed.
    fn ancestors_of(&self, id: &str) -> Vec<&str> {
        let mut out = Vec::new();
        let mut current = self.cell(id).and_then(|c| c.parent.clone());
        let bound = self.cells.len() + 1;
        let mut steps = 0;
        while let Some(pid) = current {
            if steps >= bound {
                break; // unreachable by construction; keeps the walk finite
            }
            steps += 1;
            match self.cell(&pid) {
                Some(parent) => {
                    out.push(parent.id.as_str());
                    current = parent.parent.clone();
                }
                None => break, // roots have no parent; walk ends here
            }
        }
        out
    }

    /// True when `anc` is a strict ancestor of `node`.
    fn is_ancestor(&self, anc: &str, node: &str) -> bool {
        self.ancestors_of(node).contains(&anc)
    }

    /// Lowest (nearest) common ancestor of `a` and `b`, if any.
    fn lowest_common_ancestor(&self, a: &str, b: &str) -> Option<&str> {
        self.ancestors_of(a)
            .into_iter()
            .find(|anc| self.is_ancestor(anc, b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical demo tree used across the relation/route tests:
    ///
    /// ```text
    /// r
    /// ├── a
    /// │   └── a1
    /// │       └── a1x
    /// └── b
    ///     └── b1
    ///         └── b1x
    /// ```
    fn demo_tree() -> SpawnTree {
        let mut t = SpawnTree::new();
        t.root("r", Some("p-root")).unwrap();
        t.spawn("r", "a", Some("p-a")).unwrap();
        t.spawn("r", "b", Some("p-b")).unwrap();
        t.spawn("a", "a1", None).unwrap();
        t.spawn("a1", "a1x", None).unwrap();
        t.spawn("b", "b1", None).unwrap();
        t.spawn("b1", "b1x", None).unwrap();
        t
    }

    // ---- spawn / tree shape -------------------------------------------

    #[test]
    fn root_and_spawn_build_tree_shapes() {
        let t = demo_tree();
        assert_eq!(t.len(), 7);
        assert!(!t.is_empty());
        assert_eq!(t.cell("r").unwrap().parent, None);
        assert_eq!(t.cell("r").unwrap().persona.as_deref(), Some("p-root"));
        assert_eq!(t.cell("a").unwrap().parent.as_deref(), Some("r"));
        assert_eq!(t.cell("a").unwrap().persona.as_deref(), Some("p-a"));
        assert_eq!(t.cell("a").unwrap().id, "a");
        assert_eq!(t.cell("a1x").unwrap().parent.as_deref(), Some("a1"));
        assert!(t.cell("nope").is_none());
        assert!(SpawnTree::new().is_empty());
    }

    #[test]
    fn second_root_with_distinct_id_is_allowed_as_forest() {
        // Pinned interpretation #3: no MultiRoot variant in the frozen error
        // set ⇒ distinct roots coexist and relate as unrelated.
        let mut t = demo_tree();
        t.root("r2", None).unwrap();
        assert_eq!(t.len(), 8);
        assert_eq!(t.cell("r2").unwrap().parent, None);
        assert_eq!(t.relation("r", "r2"), Ok(Relation::Unrelated));
        // …but re-using an existing id is still a duplicate.
        assert_eq!(t.root("r", None), Err(IsolationError::DuplicateCell));
    }

    #[test]
    fn empty_ids_are_rejected_with_precedence() {
        let mut t = demo_tree();
        assert_eq!(t.root("", None), Err(IsolationError::EmptyId));
        assert_eq!(t.spawn("r", "", None), Err(IsolationError::EmptyId));
        // EmptyId is checked before UnknownCell (pinned precedence).
        assert_eq!(t.spawn("ghost", "", None), Err(IsolationError::EmptyId));
        assert_eq!(t.len(), 7, "failed calls store nothing");
    }

    #[test]
    fn duplicate_cell_is_rejected() {
        let mut t = demo_tree();
        assert_eq!(t.root("a", None), Err(IsolationError::DuplicateCell));
        assert_eq!(t.spawn("r", "a", None), Err(IsolationError::DuplicateCell));
        assert_eq!(
            t.spawn("b", "b1", None),
            Err(IsolationError::DuplicateCell)
        );
        assert_eq!(t.len(), 7, "failed calls store nothing");
    }

    #[test]
    fn unknown_cells_are_rejected_everywhere() {
        let mut t = demo_tree();
        assert_eq!(t.spawn("ghost", "g1", None), Err(IsolationError::UnknownCell));
        assert_eq!(t.relation("ghost", "a"), Err(IsolationError::UnknownCell));
        assert_eq!(t.relation("a", "ghost"), Err(IsolationError::UnknownCell));
        assert_eq!(t.route("ghost", "a"), Err(IsolationError::UnknownCell));
        assert_eq!(t.route("a", "ghost"), Err(IsolationError::UnknownCell));
        assert_eq!(
            t.state_visible_to("ghost", "a"),
            Err(IsolationError::UnknownCell)
        );
        assert_eq!(
            t.state_visible_to("a", "ghost"),
            Err(IsolationError::UnknownCell)
        );
        assert_eq!(t.siblings("ghost"), Err(IsolationError::UnknownCell));
    }

    // ---- relation matrix ----------------------------------------------

    #[test]
    fn relation_pins_self() {
        let t = demo_tree();
        assert_eq!(t.relation("r", "r"), Ok(Relation::Self_));
        assert_eq!(t.relation("a1x", "a1x"), Ok(Relation::Self_));
    }

    #[test]
    fn relation_pins_parent_child_at_any_depth() {
        let t = demo_tree();
        // direct parent ↔ child
        assert_eq!(
            t.relation("r", "a"),
            Ok(Relation::ParentChild {
                direction: Direction::Down
            })
        );
        assert_eq!(
            t.relation("a", "r"),
            Ok(Relation::ParentChild {
                direction: Direction::Up
            })
        );
        // grandparent ↔ grandchild (ParentChild covers any depth)
        assert_eq!(
            t.relation("r", "a1"),
            Ok(Relation::ParentChild {
                direction: Direction::Down
            })
        );
        assert_eq!(
            t.relation("a1x", "r"),
            Ok(Relation::ParentChild {
                direction: Direction::Up
            })
        );
    }

    #[test]
    fn relation_pins_siblings() {
        let t = demo_tree();
        assert_eq!(t.relation("a", "b"), Ok(Relation::Siblings));
        assert_eq!(t.relation("b", "a"), Ok(Relation::Siblings));
        // siblings at depth: two children of `a` share the parent
        let mut t2 = demo_tree();
        t2.spawn("a", "a2", None).unwrap();
        assert_eq!(t2.relation("a1", "a2"), Ok(Relation::Siblings));
        assert_eq!(t2.relation("a2", "a1"), Ok(Relation::Siblings));
        // roots (parent None) are never siblings — no common parent to share
        let mut t3 = demo_tree();
        t3.root("r2", None).unwrap();
        assert_eq!(t3.relation("r", "r2"), Ok(Relation::Unrelated));
    }

    #[test]
    fn relation_pins_the_cousin_case() {
        let t = demo_tree();
        // Pinned: a1 and b1 sit under different child-branches of common
        // ancestor r ⇒ Cousins.
        assert_eq!(t.relation("a1", "b1"), Ok(Relation::Cousins));
        assert_eq!(t.relation("b1", "a1"), Ok(Relation::Cousins));
        // deeper (second-cousin-ish) nodes under the same branches too
        assert_eq!(t.relation("a1x", "b1x"), Ok(Relation::Cousins));
        // a node and its *branch* ancestor (uncle) are cousins, never
        // ParentChild — ParentChild requires an actual lineage chain
        assert_eq!(t.relation("a1", "b"), Ok(Relation::Cousins));
        // …whereas a node and its own lineage ancestor is ParentChild
        assert_eq!(
            t.relation("a1", "a"),
            Ok(Relation::ParentChild {
                direction: Direction::Up
            })
        );
        assert_eq!(
            t.relation("a", "a1x"),
            Ok(Relation::ParentChild {
                direction: Direction::Down
            })
        );
    }

    #[test]
    fn relation_pins_unrelated_across_roots() {
        let mut t = demo_tree();
        t.root("z", None).unwrap();
        t.spawn("z", "z1", None).unwrap();
        assert_eq!(t.relation("r", "z"), Ok(Relation::Unrelated));
        assert_eq!(t.relation("a", "z1"), Ok(Relation::Unrelated));
        assert_eq!(t.relation("z1", "a1x"), Ok(Relation::Unrelated));
        // roots are never siblings and never cousins — across roots it is
        // Unrelated in both directions
        assert_eq!(t.relation("z", "a"), Ok(Relation::Unrelated));
        assert_eq!(t.relation("a", "z"), Ok(Relation::Unrelated));
    }

    // ---- route matrix -------------------------------------------------

    #[test]
    fn route_pins_direct_only_along_the_lineage() {
        let t = demo_tree();
        assert_eq!(t.route("r", "a"), Ok(Route::Direct));
        assert_eq!(t.route("a", "r"), Ok(Route::Direct));
        assert_eq!(t.route("r", "a1x"), Ok(Route::Direct));
        assert_eq!(t.route("a1x", "r"), Ok(Route::Direct));
        assert_eq!(t.route("a", "a1"), Ok(Route::Direct));
    }

    #[test]
    fn route_pins_self_as_direct() {
        // Pinned interpretation #1 (argued deviation from the literal
        // "everything else ⇒ ViaLiaison"): a self-route crosses no cell
        // boundary, so it is not a cross-cell handoff.
        let t = demo_tree();
        assert_eq!(t.route("a", "a"), Ok(Route::Direct));
        assert_eq!(t.route("r", "r"), Ok(Route::Direct));
    }

    #[test]
    fn route_pins_via_liaison_for_everything_off_the_lineage() {
        let t = demo_tree();
        // siblings — never Direct, in either direction
        assert_eq!(t.route("a", "b"), Ok(Route::ViaLiaison));
        assert_eq!(t.route("b", "a"), Ok(Route::ViaLiaison));
        assert_ne!(t.route("a", "b"), Ok(Route::Direct));
        // cousins
        assert_eq!(t.route("a1", "b1"), Ok(Route::ViaLiaison));
        assert_eq!(t.route("b1x", "a1"), Ok(Route::ViaLiaison));
        assert_eq!(t.route("a1x", "b1x"), Ok(Route::ViaLiaison));
        // unrelated
        assert_eq!(t.route("a", "r2"), Err(IsolationError::UnknownCell));
        let mut t2 = demo_tree();
        t2.root("z", None).unwrap();
        assert_eq!(t2.route("a", "z"), Ok(Route::ViaLiaison));
    }

    // ---- blast radius (B1.3.3) ----------------------------------------

    #[test]
    fn blast_radius_compromised_child_reads_only_its_subtree() {
        // Scenario: `a` is compromised. The damage must not walk upward or
        // sideways: sibling `b`, parent `r`, cousin `b1`/`b1x` are all denied,
        // while a's own subtree (a1, a1x) stays readable.
        let t = demo_tree();
        assert_eq!(t.state_visible_to("a", "a"), Ok(()));
        assert_eq!(t.state_visible_to("a", "a1"), Ok(()));
        assert_eq!(t.state_visible_to("a", "a1x"), Ok(()));

        assert_eq!(
            t.state_visible_to("a", "b"),
            Err(IsolationError::NotAuthorized {
                viewer: "a".into(),
                owner: "b".into()
            })
        );
        assert_eq!(
            t.state_visible_to("a", "r"),
            Err(IsolationError::NotAuthorized {
                viewer: "a".into(),
                owner: "r".into()
            })
        );
        assert_eq!(
            t.state_visible_to("a", "b1"),
            Err(IsolationError::NotAuthorized {
                viewer: "a".into(),
                owner: "b1".into()
            })
        );
        assert_eq!(
            t.state_visible_to("a", "b1x"),
            Err(IsolationError::NotAuthorized {
                viewer: "a".into(),
                owner: "b1x".into()
            })
        );
    }

    #[test]
    fn blast_radius_holds_inside_a_subtree() {
        // Even two children of the same compromised cell cannot read each
        // other's state: the readable region is a subtree per viewer, and the
        // boundary holds recursively — but the parent can read down.
        let mut t = SpawnTree::new();
        t.root("r", None).unwrap();
        t.spawn("r", "v", None).unwrap(); // viewer / compromised cell
        t.spawn("v", "c1", None).unwrap();
        t.spawn("v", "c2", None).unwrap();
        t.spawn("c2", "c2x", None).unwrap();

        assert_eq!(t.state_visible_to("v", "c1"), Ok(()));
        assert_eq!(t.state_visible_to("v", "c2x"), Ok(()));
        // c1 cannot read its sibling c2, nor c2's child, nor the parent r
        assert_eq!(
            t.state_visible_to("c1", "c2"),
            Err(IsolationError::NotAuthorized {
                viewer: "c1".into(),
                owner: "c2".into()
            })
        );
        assert_eq!(
            t.state_visible_to("c1", "c2x"),
            Err(IsolationError::NotAuthorized {
                viewer: "c1".into(),
                owner: "c2x".into()
            })
        );
        assert_eq!(
            t.state_visible_to("c1", "r"),
            Err(IsolationError::NotAuthorized {
                viewer: "c1".into(),
                owner: "r".into()
            })
        );
        // visibility is downward only: parent reads child, child never reads
        // parent (checked above) — and c2 reads its own subtree.
        assert_eq!(t.state_visible_to("c2", "c2x"), Ok(()));
        assert_eq!(t.state_visible_to("c2", "c2"), Ok(()));
    }

    #[test]
    fn not_authorized_message_names_both_cells() {
        let t = demo_tree();
        let err = t.state_visible_to("a1", "b1").unwrap_err();
        assert_eq!(
            err,
            IsolationError::NotAuthorized {
                viewer: "a1".into(),
                owner: "b1".into()
            }
        );
        let msg = err.to_string();
        assert!(msg.contains("a1"), "message must name the viewer: {msg}");
        assert!(msg.contains("b1"), "message must name the owner: {msg}");
        // not-yet-decided cells have their own stable messages
        assert!(IsolationError::EmptyId.to_string().contains("empty"));
        assert!(IsolationError::DuplicateCell.to_string().contains("exists"));
        assert!(IsolationError::UnknownCell.to_string().contains("not present"));
    }

    // ---- siblings output ----------------------------------------------

    #[test]
    fn siblings_output_is_sorted_and_excludes_self() {
        let mut t = SpawnTree::new();
        t.root("r", None).unwrap();
        t.spawn("r", "c", None).unwrap(); // spawn order c, a, b
        t.spawn("r", "a", None).unwrap();
        t.spawn("r", "b", None).unwrap();
        let sibs: Vec<&str> = t.siblings("a").unwrap().iter().map(|c| c.id.as_str()).collect();
        assert_eq!(sibs, vec!["b", "c"], "sorted by id, self excluded");
        let sibs_b: Vec<&str> = t.siblings("b").unwrap().iter().map(|c| c.id.as_str()).collect();
        assert_eq!(sibs_b, vec!["a", "c"]);
        // root has no siblings; only children of the same parent count
        assert!(t.siblings("r").unwrap().is_empty());
    }

    // ---- determinism + serde ------------------------------------------

    #[test]
    fn tree_is_deterministic() {
        let t1 = demo_tree();
        let t2 = demo_tree();
        assert_eq!(t1, t2, "same call sequence ⇒ identical tree");
        for (a, b) in [
            ("r", "a"),
            ("a", "a1"),
            ("a", "b"),
            ("a1", "b1"),
            ("a1x", "b1x"),
            ("r", "a1x"),
        ] {
            assert_eq!(t1.relation(a, b), t2.relation(a, b));
            assert_eq!(t1.route(a, b), t2.route(a, b));
            assert_eq!(t1.state_visible_to(a, b), t2.state_visible_to(a, b));
        }
        let ids1: Vec<&str> = t1.siblings("a1").unwrap().iter().map(|c| c.id.as_str()).collect();
        let ids2: Vec<&str> = t2.siblings("a1").unwrap().iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids1, ids2);
    }

    #[test]
    fn serde_roundtrips_tree_and_vocabulary() {
        let t = demo_tree();
        let json = serde_json::to_string(&t).unwrap();
        let back: SpawnTree = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back, "tree survives a JSON round-trip");

        for r in [
            Relation::Self_,
            Relation::ParentChild {
                direction: Direction::Down,
            },
            Relation::ParentChild {
                direction: Direction::Up,
            },
            Relation::Siblings,
            Relation::Cousins,
            Relation::Unrelated,
        ] {
            let j = serde_json::to_string(&r).unwrap();
            let back: Relation = serde_json::from_str(&j).unwrap();
            assert_eq!(r, back);
        }

        assert_eq!(serde_json::to_string(&Route::ViaLiaison).unwrap(), "\"ViaLiaison\"");
        assert_eq!(serde_json::to_string(&Route::Direct).unwrap(), "\"Direct\"");
        let back_route: Route =
            serde_json::from_str(&serde_json::to_string(&Route::ViaLiaison).unwrap()).unwrap();
        assert_eq!(back_route, Route::ViaLiaison);

        let err = IsolationError::NotAuthorized {
            viewer: "v".into(),
            owner: "o".into(),
        };
        let j = serde_json::to_string(&err).unwrap();
        assert!(j.contains("NotAuthorized") && j.contains("\"v\"") && j.contains("\"o\""));
        let back_err: IsolationError = serde_json::from_str(&j).unwrap();
        assert_eq!(err, back_err);
        for e in [
            IsolationError::EmptyId,
            IsolationError::DuplicateCell,
            IsolationError::UnknownCell,
        ] {
            let back: IsolationError =
                serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
            assert_eq!(e, back);
        }
    }
}
