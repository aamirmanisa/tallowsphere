# Module visibility

Status: **normative for Tallow 2.0**. Backlog row G09.

## Why

`resolve_imports` merges every item of an imported file into the importing program.
Until now that merge was unconditional: a helper written for internal use became
part of every importer's namespace the moment the file was imported, and there was
no way to state otherwise. The parser enforced that absence by refusing `pub` at
item position with *"Tallow has no visibility modifiers"*. That refusal is what
this document replaces.

## Syntax

Two markers, both at item position, before the item keyword:

```tallow skip:illustrative; the `pub` markers are what this document defines
pub fn connect(host: String, port: Int) -> Bool { true }
pub struct Endpoint { host: String, port: Int }
pub(crate) fn normalise(path: String) -> String { path }
```

`pub` and `(crate)` are **contextual**: neither becomes a reserved word. `pub` may
still be used as a binding or parameter name; only the sequence *item-position*
`pub` followed by `fn` / `struct` / `enum` / `impl` / `trait` / `const` / `type`
is read as a marker. `pub(crate)` is only valid when followed by an item keyword.

Applicable items: `fn`, `struct`, `enum`, `impl`, `trait`, `const`, `type`.
Not applicable: `import` (see *Re-exports*).

## Semantics

| Marker | Visible to |
|---|---|
| none | only items **declared in the same file** |
| `pub` | every file that imports this module |
| `pub(crate)` | every file in the same **package** |

A **package** is the directory tree rooted at the entry-point file's directory.
Two files are in the same package when their canonical paths share that root.
Files outside it are external importers.

Visibility is checked **at import resolution**, not at name lookup: an item that is
not visible is never merged into the importing program, so no later phase can
resolve it by accident. This mirrors `resolve_imports`' existing behaviour of
merging before type checking.

`main` keeps its existing rule: an imported file may not contribute a `main`
(E0147). Visibility does not change that; `pub fn main` is refused as well.

### What "visible" does not mean

- It does not create namespaces. Imports stay flat; `pub` decides *whether* a name
  crosses a file boundary, not *where* it lands.
- It does not affect the two execution planes. Visibility is resolved before codegen
  and before the interpreter starts, so a program that type checks produces the same
  output on both, and an invisible name is a compile error on both.

## Errors

**E0153 — importing a private item.** Emitted when an import would merge an item
whose visibility does not reach the importer.

```
error[E0153]: `helper` is private to src/net.tl
  --> src/client.tl:3:1
   = help: mark it `pub` in src/net.tl to export it, or move the use inside that file
```

**E0154 — `pub` on an import.** Re-exports are out of scope for 2.0 and are refused
rather than silently ignored.

```
error[E0154]: `pub import` is not supported — a re-export would need a namespace to
name it through; import the item where it is needed instead
```

## Re-exports

Out of scope. `pub import` is E0154. A module that wants to expose an item from
another module re-declares it (for a function, a one-line wrapper), which is honest
about the indirection.

## Compatibility

A program with no markers behaves exactly as before: every item it imports was
previously visible, and remains visible only if it is `pub`. **This is the one
deliberate breaking change**: an existing multi-file program that imports a helper
without `pub` now fails with E0153 instead of silently working. The migration is
mechanical (add `pub` at the declaration) and the error names the file and item.

## Gates

- `tests/module_visibility.rs`: private function refused (E0153); `pub` function
  imported and called; `pub(crate)` visible in-package, refused out-of-package;
  `pub` on a struct constructible from the importer; `pub import` refused (E0154);
  `pub` usable as an ordinary identifier.
- `language_surface`: E0153 and E0154 registered (catalogue 197 → 199).
- Full `--lib` suite green, since `resolve_imports` runs for every multi-file test.
