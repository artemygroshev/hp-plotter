---
name: "HP DesignJet Working Panel"
description: "An engineering workbench for the CUPS queue and independently dated HP snapshots."
colors:
  ground: "#101820"
  rail: "#121f2c"
  surface: "#192733"
  raised: "#213441"
  text: "#e9f0f6"
  muted: "#aabeca"
  line: "#3c5363"
  accent: "#8ecdf1"
  accent-text: "#102d42"
  focus: "#bce7ff"
  danger: "#ffb5b5"
  danger-bg: "#422c32"
  warning: "#f2d39a"
  warning-bg: "#383329"
  success: "#9cd8c2"
  success-bg: "#203e37"
  lcd: "#d5e3ca"
  lcd-text: "#273d31"
  lcd-muted: "#3f5747"
  light-ground: "#eef2f5"
  light-rail: "#dde8f0"
  light-surface: "#fff"
  light-raised: "#e6eef4"
  light-text: "#162c3d"
  light-muted: "#4b6375"
  light-line: "#bacbd7"
  light-accent: "#175e8c"
  light-accent-text: "#fff"
  light-focus: "#075d97"
  light-danger: "#9c2637"
  light-danger-bg: "#ffedf0"
  light-warning: "#7c4e0f"
  light-warning-bg: "#fff3db"
  light-success: "#1d6650"
  light-success-bg: "#e1f3eb"
  ink-black: "#080c10"
  ink-cyan: "#37c0df"
  ink-magenta: "#e784b7"
  ink-yellow: "#e8cb6a"
typography:
  headline:
    fontFamily: "Plex, system-ui, sans-serif"
    fontSize: "1.875rem"
    fontWeight: 500
    lineHeight: 1.25
    letterSpacing: "-0.02em"
  headline-mobile:
    fontFamily: "Plex, system-ui, sans-serif"
    fontSize: "1.6rem"
    fontWeight: 500
    lineHeight: 1.25
    letterSpacing: "-0.02em"
  title:
    fontFamily: "Plex, system-ui, sans-serif"
    fontSize: "1.3rem"
    fontWeight: 500
    lineHeight: 1.35
  title-small:
    fontFamily: "Plex, system-ui, sans-serif"
    fontSize: "1rem"
    fontWeight: 500
    lineHeight: 1.5
  body:
    fontFamily: "Plex, system-ui, sans-serif"
    fontSize: "16px"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "Plex, system-ui, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.5
  action:
    fontFamily: "Plex, system-ui, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.4
  report:
    fontFamily: "ui-monospace, monospace"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.6
rounded:
  ink-swatch: "2px"
  badge: "5px"
  field: "6px"
  control: "7px"
  inset: "8px"
  panel: "12px"
spacing:
  micro: "4px"
  compact-gap: "7px"
  small: "8px"
  control-gap: "9px"
  compact: "10px"
  medium: "12px"
  inset-small: "14px"
  control-inline: "15px"
  inset: "18px"
  group: "20px"
  section: "22px"
  panel: "24px"
components:
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.accent-text}"
    rounded: "{rounded.control}"
    padding: "9px 15px"
  button-secondary:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.text}"
    typography: "{typography.action}"
    rounded: "{rounded.control}"
    padding: "9px 15px"
  button-secondary-hover:
    backgroundColor: "{colors.line}"
  button-quiet:
    backgroundColor: "transparent"
    textColor: "{colors.text}"
    typography: "{typography.action}"
    rounded: "{rounded.control}"
    padding: "9px 15px"
  input:
    backgroundColor: "{colors.ground}"
    textColor: "{colors.text}"
    typography: "{typography.body}"
    rounded: "{rounded.field}"
    padding: "9px 11px"
  navigation-active:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.accent}"
    rounded: "{rounded.control}"
    padding: "10px"
  badge-warning:
    backgroundColor: "{colors.warning-bg}"
    textColor: "{colors.warning}"
    typography: "{typography.label}"
    rounded: "{rounded.badge}"
    padding: "4px 9px"
  notice-danger:
    backgroundColor: "{colors.danger-bg}"
    textColor: "{colors.danger}"
    typography: "{typography.label}"
    rounded: "{rounded.field}"
    padding: "12px 14px"
  panel:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.panel}"
    padding: "24px"
  lcd-frame:
    backgroundColor: "{colors.lcd}"
    textColor: "{colors.lcd-text}"
    rounded: "{rounded.inset}"
    padding: "18px"
---

# Design System: HP DesignJet Working Panel

## Overview

**Creative North Star: "The Engineering Workbench"**

The panel retains its engineering identity: deep blue surfaces, a calm blue action accent, IBM Plex Sans, and familiar forms and tables. It is a browser interface for checking a plotter from a computer or phone. The visual language favors readable status, explicit actions, and compact technical detail.

Source and freshness are part of the interface. The CUPS queue and saved HP readings occupy distinct containers with their own timestamps and status text. Diagnostic detail remains available through disclosures; an unknown reading stays unknown. The light theme uses the same hierarchy and component geometry.

**Key Characteristics:**
- Tonal blue surfaces with thin structural borders.
- IBM Plex Sans for Russian interface text and tabular numbers for operational data.
- Independent queue and snapshot status, expressed with words and semantic color.
- Intrinsic columns, text-aware navigation widths, and stacked phone layouts.
- Restrained state transitions and native browser controls.

## Colors

The palette combines cool engineering blues with restrained amber, red, and green status pairs. The frontmatter records the dark defaults and explicit light-theme counterparts; the stylesheet switches the underlying semantic variables together. The sidecar's synthesized tonal ramps are preview aids, not additional runtime palette tokens.

### Primary

- **Instrument Blue** (`accent`): links, primary actions, selected navigation, file-upload icon, and active LCD phase text. Use its paired `accent-text` for filled primary controls.
- **Focus Blue** (`focus`): the keyboard-focus outline. It remains distinct from the fill of a primary control.

### Secondary

- **Warning Amber** (`warning`, `warning-bg`): saved or stale readings and cautionary explanations. An HP snapshot badge remains cautionary even when a snapshot has been received.
- **Fault Red** (`danger`, `danger-bg`): failed requests, queue stops, confirmed error messages, and unavailable connection status.
- **Queue Green** (`success`, `success-bg`): successful form results and an empty CUPS queue. This color does not establish physical HP readiness.

### Tertiary

- **LCD Sage** (`lcd`, `lcd-text`, `lcd-muted`): the saved monochrome screen's frame and captions. These values remain the same in both themes.
- **Ink Identification** (`ink-black`, `ink-cyan`, `ink-magenta`, `ink-yellow`): small labeled printhead swatches. They identify ink channels rather than health states.

### Neutral

- **Workbench Ground** (`ground`): page canvas, field interiors, image previews, and raw report backgrounds.
- **Navigation Rail** (`rail`): the persistent desktop navigation plane.
- **Panel Blue** (`surface`): the main containers and confirmation dialog.
- **Raised Blue** (`raised`): default control fills, selected navigation, neutral badges, and drag feedback.
- **Primary Text** (`text`): headings, values, and control labels.
- **Supporting Text** (`muted`): timestamps, explanatory copy, table headings, and secondary identifiers.
- **Structural Line** (`line`): borders, dividers, and secondary button hover fill.

**The Independent Status Rule.** Queue success must never imply that the physical plotter is Ready. Keep each status beside its own source and timestamp.

## Typography

**Interface Font:** IBM Plex Sans, registered as `Plex`, with `system-ui, sans-serif` fallbacks. Regular, Medium, and SemiBold are self-hosted and use font-display swap; the accompanying font files retain their OFL license.

**Technical Font:** `ui-monospace, monospace` for raw parameter names and the preserved reset report.

**Character:** A single humanist sans family keeps Cyrillic labels, file names, and numeric controls coherent. Weight establishes hierarchy without oversized display typography.

### Hierarchy

- **Headline:** page title; the smaller mobile role applies at the phone breakpoint.
- **Title:** section headings.
- **Small title:** form headings, subsection headings, and printhead names.
- **Body:** interface defaults and field values; paragraphs have a maximum measure of 72 characters and allow long values to wrap.
- **Label:** supporting text, timestamps, table content, notices, and compact control labels. Navigation and primary actions use Medium; strong values use SemiBold.
- **Report:** literal reset output, preserving line breaks while wrapping long content. Raw parameter names use the same monospace family at the label size and inherit the normal body line-height.

**The Operational Numbers Rule.** Buttons, badges, table cells, and definition-list values use tabular numerals so changing readings do not disturb alignment.

## Layout

The desktop shell uses a text-aware navigation track (`13.125rem`) and a flexible main track (`minmax(0, 1fr)`). The rail sticks to the viewport, with its supporting links at the bottom. The main area fills available width up to a maximum of 1760px, is centered, and normally has 30px horizontal padding. Above the wide-screen breakpoint, horizontal padding increases to 42px.

The first workspace uses intrinsic columns: `repeat(auto-fit, minmax(min(100%, 28rem), 1fr))`, with a 22px gap. It forms two equal columns only when both fit; long content must not force the page wider. Panels use `min-width: 0`. Later data panels span the main area. Standard panel padding is the panel spacing token; related control and content gaps use the compact-to-section spacing steps rather than a strict arithmetic scale.

At 1150px and below, the rail narrows to `11.25rem`, main padding becomes 24px vertically and 20px horizontally, and the workspace becomes one column. Within the HP panel, the LCD and message sit side by side, using a minimum 240px screen column and a flexible message column. The printhead summary becomes two columns. The header wraps as needed.

At 680px and below, navigation becomes a static top rail with a horizontally scrollable link row; supporting rail links are hidden. Main padding becomes 22px vertically and 14px horizontally; panel padding becomes 19px vertically and 17px horizontally. The HP panel returns to a single flow, form fields stack, section headings wrap, search fills its row, and definition-list values wrap below their labels when necessary. Printhead summaries remain in two columns.

Active jobs become stacked rows on phones: the table header is hidden, title and state appear above the wrapping action group, and job buttons have a minimum 44px height. Technical history tables retain local horizontal scrolling. Keep overflow inside the relevant table container rather than widening the page.

**The Text-Aware Layout Rule.** Preserve rem-based navigation widths, shrinkable content tracks, wrapping text, and stacked mobile job actions when extending the panel.

## Elevation & Depth

The interface has no box-shadow vocabulary. Depth comes from the ground, rail, surface, and raised tones, together with thin borders and section dividers. The confirmation dialog uses the panel surface over a dark translucent backdrop (`rgba(4,12,19,.75)`). Focus is an outline rather than an elevation effect.

**The Tonal Depth Rule.** Use the existing surface layers and borders for structural separation; do not add shadows to ordinary panels or controls.

## Shapes

Containers have gently rounded panel corners. Controls are tighter, fields and notices use the field radius, badges use the badge radius, and inset upload/LCD regions use the inset radius. The tiny ink swatch uses its own small corner token. Borders are normally one pixel; the upload target is dashed. Shapes remain identical in both themes.

Interface icons are inline SVG line drawings using current text color, rounded caps and joins, and a 1.6-unit stroke. Normal icons are 21px square, with contextual sizes for branding, empty states, and mobile navigation. Their accompanying labels carry the action or status meaning.

## Components

### Buttons

Buttons are compact, labeled controls with at least 44px height by default, the control corner token, and a one-pixel structural border. Secondary buttons use the raised fill; quiet buttons use a transparent fill; primary buttons use the accent pair and Medium weight. The form submission action spans the panel width.

Secondary and quiet buttons change to the line fill on hover. Enabled primary buttons brighten to 1.08 on hover. All buttons move down one pixel when active. Disabled controls use half opacity and a not-allowed cursor. Background transitions last 140ms with ease-out timing.

Job and LCD-phase actions use compact label text and a 36px minimum height on larger screens; phone job actions expand to 44px. The selected LCD phase is indicated by `aria-pressed`, a raised fill, and accent text. Disabled phases remain visible when their saved image is unavailable.

### Inputs / Fields

Number inputs, search, and selects use the ground fill, text color, a structural border, the field radius, and at least 44px height. Visible labels sit above the fields; helper copy explains fixed width and fitting behavior. Checkboxes use the accent color and a 19px square native control.

The upload region keeps a real file input alongside its dashed drop target. Dragging changes the border to accent and adds a raised fill. A selected image may show a contained thumbnail and dimensions; a PDF has a text summary. Long names wrap. Invalid type, size, empty file, preview failure, and submission failure use explicit form text rather than color alone.

### Navigation

Desktop links combine SVG and Medium text, with a 48px minimum height and compact corner radius. Muted text is the default; hover uses primary text and a raised fill. The current link uses accent text and the same raised fill, with `aria-current` carrying the selected state. Phone links use the label size, a 42px minimum height, and a single horizontally scrollable row.

### Badges / Notices

Badges are status labels, not buttons. They have compact padding, a minimum 28px height, and a maximum width of half the heading row; labels may wrap. Neutral, warning, danger, and success variants use their matching color pairs. Notices give longer explanations at label size with comfortable line-height and a field-shaped container. Never leave a color without explanatory text.

### Cards / Containers

Panels share the surface, line border, panel radius, and responsive padding. Section headings put the heading and source/status information together. Thin dividers separate a form or diagnostic detail within the same container. Expandable histories and raw values use native `details` and `summary`; they remain keyboard operable.

### Saved HP Screen

The LCD sits in a sage inset and preserves the raster's pixelated rendering. A saved 128×64 screen scales with the container up to 512px wide, retaining its aspect ratio. Each phase has its own caption and recorded time. Keep the snapshot timestamp, stale warning, literal message, and diagnostic limitation visible together; the screen is evidence from a saved read, not a live video feed.

### Queue and Data States

Initial loading, empty queue, populated jobs, inaccessible queue, and stopped CUPS have distinct copy. A failed queue read hides the old active rows and empty state, removes actionable queue authority, and states that the current state is unconfirmed. The print action stays disabled until both a valid file and queue permission exist.

The browser refreshes the queue and cached HP endpoints every 15 seconds while visible; snapshot age is reevaluated every 30 seconds. Refresh reads stored HP data and does not restart physical HP polling. Saved HP data older than one hour, or without a latest snapshot, carries the stale warning. If the HP cache request fails after a prior success, the saved screen can remain visible while the connection badge and explanation report the failure. Other unavailable histories clear their rendered rows or report text and state that the saved information could not be loaded.

Confirmation dialogs name the file or job, explain the action, and provide a return action. Submission lists sheet dimensions, quality, copy count, fitting, and the PDF first-page limit. A timeout asks the operator to check the queue before repeating; CUPS completion is described as a queue result rather than proof of a physical print.

### Keyboard, Motion, and Contrast

Links, buttons, fields, selects, and disclosure summaries use a three-pixel focus outline with four-pixel offset. A skip link becomes visible on focus. Status messages and the HP message use appropriate live text regions. Dialogs use the native modal element and initially focus the return button.

Reduced motion disables transitions and animations and makes scrolling immediate. Forced-colors mode adds status borders, preserves labeled ink swatch colors, and strengthens the primary-button border. Theme preference is stored locally when browser storage is available; the default theme is dark.

## Do's and Don'ts

### Do:

- **Do** keep queue and saved HP status independently dated and explicitly labeled.
- **Do** use the semantic variable pairs for both themes and retain text labels beside status colors.
- **Do** preserve IBM Plex Sans, tabular operational numbers, and monospace literal reports.
- **Do** keep long file names and diagnostic values wrappable, with local overflow for technical tables.
- **Do** retain visible focus, native controls, reduced-motion behavior, and stacked phone job actions.
- **Do** state unavailable, stale, and uncertain results in the container that owns them.

### Don't:

- **Don't** equate an empty or completed CUPS queue with physical printer readiness or print quality.
- **Don't** present cached HP readings as a live physical poll or silently remove their age.
- **Don't** invent a hardware cause when the evidence identifies only a code or an electrical error category.
- **Don't** turn raw service values into ink percentages without a confirmed interpretation.
- **Don't** add ornamental shadows or replace labeled interface icons with font glyphs.
- **Don't** widen the page to fit a table, long value, or job action group.
