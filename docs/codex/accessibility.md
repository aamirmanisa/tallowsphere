# Accessibility

- Every interactive control must have an accessible name.
- Prefer native HTML elements before adding ARIA.
- All interactive UI must be keyboard reachable and visibly focusable.
- Dialogs must trap focus, restore focus on close, and close on `Escape` when appropriate.
- Inputs need labels, field-level errors, and associated helper text.
- Use `aria-live`, `aria-busy`, `aria-expanded`, and `aria-controls` only where they carry real state.
- Avoid hover-only or color-only communication for important actions or status.
