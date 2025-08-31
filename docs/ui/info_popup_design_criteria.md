# Chart Info Popup – Design Criteria

Goals
- Present consistent, authoritative, and actionable explanations for each chart.
- Open fast, read easily, and never block the main UI.

Content structure
- Title: “<Chart Name> – Info”.
- Summary: 1–2 sentences on what the metric shows and why it matters.
- Details:
  - Definition: formula, units, scope (Overall/IPv4/IPv6), normalization caveats.
  - Interactions: overlays, toggles, where to configure them.
  - Limits/edge cases and interpretation notes.
- Tips (mandatory): include X-Axis, Y-Scale, Number of Batches, Situation filter, and export watermark note.
- References (mandatory): 1–3 authoritative, clickable URLs (RFCs/IANA/MDN/vendor specs).

Window behavior
- Opens as a resizable child window.
- Minimum content size: 520×360; content is scrollable.
- Remembers last size (persist width/height) across app runs.
- Opens centered relative to the main window; does not block the main UI.

Interaction
- Close via OS window controls; support common shortcuts (e.g., Cmd+W on macOS) if available.
- Links open in the default browser; clearly visible and wrap long URLs.
- Multiple Info windows can be open simultaneously.

Visual and readability
- Rich text with word wrapping and adequate spacing; good contrast in light/dark themes.
- Clear headings: “References”, “Tips”; bullet lists for scanability.

Accessibility and i18n
- Info button has accessible label/tooltip (e.g., “Info about <Chart Name>”).
- Keyboard navigable content (Tab between links).
- Strings centralized to allow localization; avoid idioms/jargon where possible.

Links policy
- Prefer standards first (RFCs/IANA), then MDN/Wikipedia, then vendor docs.
- Use canonical URLs without tracking parameters.
- No in-dialog network fetches; links only.

Performance and reliability
- Build content lazily on open; no background work.
- Safe rendering when no URLs (hide “References” header).
- Handle extremely long/missing text gracefully.

Persistence
- Preference keys: `infoPopupW`, `infoPopupH` (ints), clamped to minimum size.
- Backward-compatible defaults if prefs are missing.

Definition of Done
- All charts: Summary, Details, Tips, and References included.
- Links are clickable and open externally.
- Window size persists across sessions; minimum enforced.
- Verified in light and dark themes.
- Non-blocking: main window remains responsive.
