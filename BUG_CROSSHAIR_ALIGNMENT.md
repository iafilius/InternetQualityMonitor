# BUG: Crosshair X-axis Calibration/Alignment (Index Mode)

Status: Open
Date: 2025-08-29
Owner: TBD

## Summary
In the viewer’s index-mode charts, the crosshair’s vertical line and tooltip can drift off the exact tick/point as batch counts or chart layout varies. A provisional image-based calibration (gridline detection) improves alignment but is not yet reliable across all themes/layouts. We’re deferring further calibration work and tracking this bug here.

## Reproduction
- Open iqmviewer and load any dataset with multiple batches (>= 8 is good).
- Switch X-axis to “Batch Index/Run Tag” mode (not time).
- Hover across points from left to right.
- Observe that the vertical crosshair can be slightly offset from the tick/point center in some cases.

Notes:
- The drift is more visible at certain container sizes/aspect ratios and when contain-fit introduces padding.
- Headless screenshot tests log the issue less, but visual inspection in the app highlights it.

## Expected
- Crosshair snaps to the nearest plotted X exactly (ticks/points), consistently across sizes/themes.
- Tooltip content always reflects the snapped X (already true in tests).

## Actual
- Crosshair snaps logically to the right index, but the vertical line may not be pixel-perfect aligned to the visible tick/point for some charts.

## Scope
- Index-mode charts using categorical X (batch index or run tag).
- Time-mode mapping is already robust.

## Suspected Root Cause
- Mismatch between estimated inner-plot gutters and go-chart’s actual layout.
- Theme/renderer differences for gridlines and axes affect calibration.
- Contain-fit scaling composes with image paddings; rounding can compound.

## Current Implementation Notes
- We compute contain-fit geometry and try to calibrate X centers by detecting major gridlines from the rendered PNG (image pixel space), mapping them into overlay space. If detection fails, we fall back to math-based centers.
- Tests include an image-based harness that detects centers and verifies snapping/labels; however, UI alignment still isn’t perfect in all cases.

## Acceptance Criteria
- Crosshair vertical line visually aligns with the exact center of the nearest tick/point across:
  - Light and Dark themes
  - Varying chart sizes/aspect ratios
  - N in [2, 40] batches
- No perceptible drift during hover; tooltip content remains correct.
- Calibration resilient when gridlines are disabled (fallback remains visually acceptable).

## Proposed Fix Directions
- Derive exact plot area from go-chart (if API allows) rather than empirical gutters.
- Encode/calibrate X coordinates during chart render, and emit them alongside the image for the overlay to consume (source-of-truth approach).
- Improve gridline detection:
  - Detect both gridline and dot/marker centers; combine signals.
  - Adaptive color tolerance per theme; skip anti-aliased blends.
- Quantize to integral device pixels after contain-fit to minimize rounding drift.

## Tasks
- [ ] Investigate go-chart APIs or forking to expose inner plot rect and per-series X coordinates.
- [ ] Prototype emit-and-consume X center metadata during render.
- [ ] Harden image-based detection (themes, anti-aliasing, gutters).
- [ ] Add a visual regression test that draws known markers and asserts sub-pixel alignment.
- [ ] Verify across sizes and themes; update tests accordingly.

## References
- See crosshair renderer code in `cmd/iqmviewer/main.go` (`crosshairRenderer.Layout`).
- Image-based tests in `cmd/iqmviewer/main_test.go`.
