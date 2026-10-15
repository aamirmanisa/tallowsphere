# Motion Performance

- Default to `transform` and `opacity`.
- Do not animate layout continuously on large surfaces.
- Avoid interleaving DOM reads and writes in the same frame.
- Use `IntersectionObserver` or equivalent to pause off-screen motion.
- Treat blur, filters, and paint-heavy animation as small-surface exceptions only.
- Do not mix multiple animation systems inside the same interaction without a strong reason.
- Prefer cheaper techniques over deleting motion entirely when preserving intent matters.
