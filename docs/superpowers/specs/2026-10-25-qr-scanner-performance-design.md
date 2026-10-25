# QR Scanner Performance and Display Design

## Intent

Make the New Device camera preview responsive and QR scanning practical, while keeping camera decoding from blocking the UI. Give the Old Device QR a deliberate, centered footprint instead of letting the label expand across the page.

## Goals and constraints

- Keep the existing New Device scans / Old Device displays flow and the five-minute session expiry.
- Update the preview independently from QR decode cadence.
- Decode QR-only frames asynchronously with at most one decode in flight; discard stale results after cancel, expiry, or screen changes.
- Use ZXing's fast path settings for ordinary QR scanning and preserve a fallback if needed for rotated or low-quality codes.
- Display the QR in a centered square card around 300 px, with a four-module quiet zone and no oversized backing pixmap.
- Keep Qt UI changes in `AuthQt`; do not change protocol or vault formats.

## Approaches

1. Tune synchronous decoding and preview cadence. This is simpler, but a decode can still pause touch input and preview rendering.
2. Decode asynchronously with a single in-flight job, tune QR-only reader options, and decouple preview updates. Selected because the current synchronous decode blocks the UI and couples preview to a five-frame skip.

## Implementation calls

- Use Qt Concurrent/`QFutureWatcher` for worker decoding, retaining only the latest selected frame and ignoring results after scan state changes.
- Prefer the rear camera and cap capture at the largest supported format up to 1280×720, avoiding unnecessarily large camera frames.
- Limit unnecessary ZXing rotation/inversion/downscale work in the fast path; keep a slower fallback for frames that fail the first decode.
- Render the QR near 300 px in a centered fixed/preferred-size card; do not scale the QR to fill the app page.
- Keep all existing protocol validation and camera permission handling.

## Verification

- Build desktop `AuthQt` and run the QR Sync tests.
- Build the Android APK.
- Physical-device scan latency and camera behavior still need confirmation on hardware.
