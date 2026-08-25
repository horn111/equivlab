---
name: EquivLab
description: A calibrated consensus-safety inspection bench for exact contract revisions.
colors:
  ink: "#d9d5c9"
  ink-strong: "#f2eee3"
  ink-muted: "#989b93"
  graphite-0: "#101311"
  graphite-1: "#151917"
  graphite-2: "#1b201d"
  line: "#3f4641"
  line-bright: "#686e68"
  amber: "#f0c83b"
  cyan: "#62b1bd"
  violet: "#9277bd"
  fail: "#ed735e"
  warn: "#e5aa58"
  success: "#90bd70"
  unverifiable: "#6c9ec6"
typography:
  display:
    fontFamily: "Barlow Condensed, sans-serif"
    fontSize: "clamp(42px, 4.2vw, 70px)"
    fontWeight: 400
    lineHeight: 0.94
    letterSpacing: "-0.02em"
  headline:
    fontFamily: "Barlow Condensed, sans-serif"
    fontSize: "clamp(28px, 2.5vw, 39px)"
    fontWeight: 400
    lineHeight: 1
    letterSpacing: "0.01em"
  title:
    fontFamily: "Barlow Condensed, sans-serif"
    fontSize: "25px"
    fontWeight: 400
    lineHeight: 1.08
  body:
    fontFamily: "IBM Plex Sans, sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.6
  label:
    fontFamily: "Barlow Condensed, sans-serif"
    fontSize: "12px"
    fontWeight: 500
    lineHeight: 1
    letterSpacing: "0.12em"
  mono:
    fontFamily: "IBM Plex Mono, monospace"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "0.04em"
rounded:
  calibrated: "1px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "20px"
  xl: "30px"
  2xl: "48px"
components:
  button-primary:
    backgroundColor: "{colors.amber}"
    textColor: "#171a16"
    typography: "{typography.label}"
    rounded: "{rounded.calibrated}"
    padding: "0 14px"
    height: "44px"
  button-primary-hover:
    backgroundColor: "#ffda4b"
    textColor: "#171a16"
    typography: "{typography.label}"
    rounded: "{rounded.calibrated}"
    padding: "0 14px"
    height: "44px"
  button-secondary:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    typography: "{typography.label}"
    rounded: "{rounded.calibrated}"
    padding: "0 14px"
    height: "44px"
  input-source:
    backgroundColor: "{colors.graphite-0}"
    textColor: "{colors.ink-strong}"
    typography: "{typography.mono}"
    rounded: "{rounded.calibrated}"
    padding: "0 13px"
    height: "44px"
  status-fail:
    backgroundColor: "transparent"
    textColor: "{colors.fail}"
    typography: "{typography.label}"
    rounded: "{rounded.calibrated}"
---

# Design System: EquivLab

## Overview

**Creative North Star: "Emission Rail"**

EquivLab is an inspection bench, not a dashboard. Twelve deterministic policy rules register against one calibrated rail while exact source identity, emitted findings, and report provenance occupy distinct work regions. The composition is technical, adversarial, and restrained: graphite instrument surfaces, bone text, hairline construction, and square controls give every state a place and every divider a job.

The system makes authority visible through structure. Cyan identifies local measurement and active inspection, amber is reserved for deliberate action and keyboard focus, and violet marks the separate on-chain boundary. Result colors annotate categorical evidence; they never become a synthetic score or imply formal verification, certification, or a security guarantee.

**Key Characteristics:**

- One calibrated rail or sequence provides orientation; content is not flattened into equal cards.
- Dense information remains legible through strict type roles, a 12px data floor, hairline dividers, and repeated measurement marks.
- Square, 44px-tall controls feel mechanical and keyboard-ready.
- Local deterministic analysis and on-chain authority use visibly different regions and accents.
- Status always combines a written label with a geometric signal or icon.

## Colors

The palette behaves like a dark instrument panel: quiet graphite and bone carry most of the interface, while scarce spectral accents identify actions, evidence, and authority.

### Primary

- **Action Amber** (`amber`): the sole primary-action fill, active calibration mark, text selection, caret, and visible focus color.
- **Measured Cyan** (`cyan`): local analysis, selected evidence, active toggles, and inspection cues that are informative rather than authoritative.

### Secondary

- **Attestation Violet** (`violet`): reserved for the separate registry boundary and authoritative-readback language.

### Tertiary

- **Failure Coral** (`fail`): policy failures, interrupted analysis, and explicit error evidence.
- **Bounded Warning** (`warn`): categorical warnings that require attention without collapsing into failure.
- **Baseline Green** (`success`): implemented-rule passes only; it does not communicate general safety.
- **Unverifiable Blue** (`unverifiable`): facts or source identity that cannot be established, rendered as a distinct outcome rather than a muted failure.

### Neutral

- **Bone Ink** (`ink`): default readable foreground.
- **Bright Bone** (`ink-strong`): headings, entered source values, and primary identifiers.
- **Instrument Gray** (`ink-muted`): descriptions, labels, and inactive information.
- **Deep Graphite** (`graphite-0`): page floor and editor well.
- **Panel Graphite** (`graphite-1`): rails, navigation bands, and primary surfaces.
- **Active Graphite** (`graphite-2`): hover and selected-row fill.
- **Construction Line** (`line`): default dividers and table rules.
- **Calibrated Line** (`line-bright`): field outlines, control borders, and stronger measuring marks.

### Named Rules

**The Spectral Rarity Rule.** Amber, cyan, and violet are signals, not decoration; a region earns an accent by representing action, local measurement, or separate authority.

**The Categorical Color Rule.** Failure, warning, baseline, and unverifiable colors label explicit states and always travel with text or an icon.

## Typography

**Display Font:** Barlow Condensed (with sans-serif fallback)
**Body Font:** IBM Plex Sans (with sans-serif fallback)
**Label/Mono Font:** IBM Plex Mono (with monospace fallback)

**Character:** Condensed uppercase display type gives headings and controls the cadence of stamped instrument labels. IBM Plex Sans carries explanatory prose, while IBM Plex Mono binds source paths, hashes, policy IDs, rule IDs, and other reproducible facts to a machine-readable voice.

### Hierarchy

- **Display** (400, fluid 42–70px, 0.94): major workflow assertions, uppercase, balanced, and held to a compact measure around 12 characters wide.
- **Headline** (400, fluid 28–39px, 1): region headings such as spectra, archives, and boundaries, normally uppercase.
- **Title** (400, 25px, 1.08): finding summaries and compact sectional titles.
- **Body** (400, 15px, 1.6): explanations and boundary language, generally capped near 66 characters per line; expands to 16px on wide workstations.
- **Label** (500, 12px, tracked): actions, field labels, state names, and navigation language, uppercase with deliberate spacing.
- **Mono** (400, 12px, 1.5): exact identifiers, source content, line numbers, severities, hashes, and timestamps; key workstation data may expand to 13–14px.

### Named Rules

**The Exact Facts Rule.** Any value a reviewer may reproduce or compare belongs in mono: commits, hashes, paths, rule IDs, addresses, and report identifiers.

**The Condensed Command Rule.** Use Barlow Condensed for commands and structural headings, not for long explanatory paragraphs.

## Layout

The desktop shell anchors a sticky policy rail at 232px and gives the remaining width to the workbench. Wide workstations use an intentionally unequal source/report split; narrower workstations turn those regions into a sequential vertical flow before either side becomes cramped. Hairline borders, not gaps or floating cards, separate functional zones. Major regions use fluid 26–46px insets; compact controls and data rows work on a tighter 8–20px rhythm.

At 1400px, source and report stack so exact values and rule states remain readable. At 1250px, the rail contracts to 204px and the compact registry boundary reflows. At 820px, the rail reduces to the complete brand lockup plus the current rule ID, fixture choices become one labeled native select, source fields collapse to one column, and evidence stacks. At 560px, headings settle near 40px, page insets reduce to 16px, secondary spectrum columns hide, actions become full-width where needed, and wide comparison data remains horizontally scrollable rather than crushed.

**The Continuous Bench Rule.** Construct one divided working surface; do not replace adjacent regions with a grid of equal rounded cards.

**The Orientation Survives Rule.** Preserve the active rule at every width. The full rail belongs to desktop; mobile keeps the current rule in the branded header and uses the report spectrum as its single rule navigator.

## Elevation & Depth

The system is flat by default and uses no ambient card shadows. Depth comes from graphite steps, hairline borders, inset editor wells, and a few status glows attached to tiny marks. Glows never sit under whole containers; they signal active calibration or a categorical rule result.

### Shadow Vocabulary

- **Active Rail Glow** (`0 0 12px rgb(240 200 59 / 35%)`): a soft amber halo behind the selected rule tick.
- **Local Workbench Glow** (`0 0 10px rgb(98 177 189 / 35%)`): a restrained cyan halo around the local-workbench activity dot.
- **Passing Mark Glow** (`0 0 9px rgb(144 189 112 / 50%)`): a compact green halo around a spectrum pass mark.
- **Failure Mark Glow** (`0 0 10px rgb(237 115 94 / 55%)`): a compact coral halo around a spectrum failure mark.

### Named Rules

**The Flat Bench Rule.** Surfaces stay flat; use tonal steps and dividers for hierarchy, reserving glow for a small state-bearing mark.

## Shapes

The form language is square, thin, and calibrated. Interactive rectangles use a nearly imperceptible 1px corner softening, fields use one-pixel outlines, and selectors appear as ticks, bars, squares, and ruled rows. The brand mark, policy rail, spectrum, source controls, and status marks all repeat this linear geometry.

**The Square Instrument Rule.** Do not introduce pills, large corner radii, soft blobs, or rounded floating cards; controls should read as components of a bench instrument.

## Components

### Buttons

Buttons are compact mechanical commands with uppercase condensed labels and a minimum 44px target.

- **Shape:** square calibrated rectangle with 1px corner softening.
- **Primary:** Action Amber fill with dark ink, 14px horizontal padding, and a 44px minimum height.
- **Hover / Focus:** primary hover brightens; secondary hover gains an Active Graphite fill. All keyboard focus uses a 2px amber outline with 3px offset.
- **Secondary / Ghost:** transparent with a Calibrated Line border and Bone Ink; icon-only or text-link actions keep the same type and focus language.
- **Disabled:** reduced opacity and a not-allowed cursor; disabled appearance never masquerades as an available action.

### Chips

- **Style:** policy identifiers and compact state labels are square, mono or condensed, and bordered with Construction Line or left transparent when embedded in data.
- **State:** selected fixtures use a graphite fill plus a thicker categorical signal bar; status chips combine explicit text with an icon.

### Cards / Containers

- **Corner Style:** square; no card radius.
- **Background:** contiguous graphite steps establish grouping.
- **Shadow Strategy:** no container shadow; see the Flat Bench Rule.
- **Border:** one-pixel Construction Line, upgraded to Calibrated Line only for controls or a stronger boundary.
- **Internal Padding:** 20–30px for compact regions and fluid 26–46px for primary work regions.

### Inputs / Fields

- **Style:** Deep Graphite fill, Calibrated Line outline, Bright Bone mono text, amber caret, 44px minimum height, and 1px corner softening.
- **Focus:** 2px amber outline with 3px offset; hover lightens the field border.
- **Error / Disabled:** errors sit in a dark coral-toned ruled container with an explicit icon and recovery action.

### Navigation

The policy rail is the signature desktop orientation system. Each item combines a zero-padded index, a line tick, and an exact rule ID. Its vertical spine begins and ends inside the rule register so it reads as navigation structure, never as an incidental line through the brand or policy header. Arrow keys move through the roving-focus set. On mobile, the full rail is removed rather than duplicated as a horizontal scroller; the complete brand lockup and current rule remain visible, and the post-analysis spectrum becomes the single rule navigator.

### Brand Lockup

The complete lockup combines a custom square vector mark with the EquivLab wordmark and the descriptor “Consensus diagnostics.” The mark uses opposing calibrated brackets, three converging emission rails, and one amber result node. It must remain a bounded symbol; never extend its strokes into neighboring layout regions.

### Rule Spectrum

The spectrum is progressively disclosed only after a reproduced report exists. Each rule is a dense ruled row with a number, exact ID, human title, severity, calibrated signal, and written state. A centered bar supplies the visual reading, but the state word remains mandatory. Selecting either a desktop rail item or spectrum row updates one compact global ruled band between the fixture control and the workbench. Full evidence and the bounded next change remain in the deeper readout.

### Local Report Snapshots

Shared links and browser-restored history are explicitly labeled `UNVERIFIED SNAPSHOT`. They may restore exact source identity, but they never restore a trusted result into the active workbench. The user must reproduce the analysis against the current analyzer before comparison or result language becomes available. The recent-report archive is browser-local, capped at twelve entries, and never presented as an on-chain record.

### Source Preview Toggle

The preview switch is a compact square track with a small graphite-to-cyan thumb. It sits inside a first-class analyzed-material state that says `Bundled fixture preview` and `not fetched from GitHub`; source mode must never be inferred from a toolbar control alone.

### Workflow Disclosure

The primary flow is `Pin source → Inspect local report → Attest`. Before analysis, no empty twelve-rule table or registry controls compete with source identity. A successful analysis collapses the code editor and reveals the spectrum, evidence, interpretation boundary, and a compact registry boundary. Browser-local history stays collapsed until requested. Unconfigured authority never displays simulated transaction stages.

## Do's and Don'ts

### Do:

- **Do** organize complex evidence as contiguous ruled regions with one dominant rail or sequence.
- **Do** preserve the separate visual authorities: cyan for local measurement, violet for on-chain readback, and amber for deliberate action.
- **Do** pair every categorical state color with a written label, icon, signal shape, or combination of them.
- **Do** keep exact identifiers in mono and make them truncatable, wrap-safe, or scrollable without changing their value.
- **Do** retain 44px interactive targets, visible amber focus, keyboard operation, and reduced-motion behavior.
- **Do** keep the complete vector lockup intact and terminate structural rails inside the component that owns them.
- **Do** place immediate rule-selection feedback in the current viewport and reserve result language for completed reports.

### Don't:

- **Don't** turn the workbench into an equal-card dashboard or soften it with rounded containers and pills.
- **Don't** use accent color as atmosphere; every accent must encode action, local evidence, authority, or a named state.
- **Don't** use a green baseline state to imply certification, formal verification, or a security guarantee.
- **Don't** visually merge deterministic local findings with an authoritative on-chain record.
- **Don't** replace exact categorical findings with a synthetic score, gauge, or generic security badge.
