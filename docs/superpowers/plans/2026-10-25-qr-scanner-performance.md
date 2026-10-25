# QR Scanner Performance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep New Device scanning responsive and show the Old Device QR in a centered, bounded display area.

**Architecture:** Throttle preview rendering independently from decode attempts. Submit one QR decode at a time through Qt Concurrent, return decode results to the UI thread, and discard stale results after cancel/expiry. Render the sender code at display resolution inside a centered QR card.

**Tech Stack:** C++17, Qt 6 Widgets/Core/Multimedia/Concurrent, ZXing-C++.

**Spec:** `docs/superpowers/specs/2026-10-25-qr-scanner-performance-design.md`

## Global Constraints

- Keep New Device scanning and Old Device QR display roles.
- Keep the 300-second pairing expiry and existing payload validation.
- Keep Qt UI dependencies out of `AuthLib`.
- Preserve the QR payload wire format and vault format.
- Do not commit or push.

## Review Focus

- Cancel or expiry while a worker decode is running: late results must be ignored.
- Tab destruction while a worker is running: worker must not capture or access the tab.
- Rotated/low-light QR: fast path should retain rotation support and retry with thorough options periodically.
- Narrow or short viewport: QR card must stay within the page and controls remain reachable.
- Large frame sizes: preview and decoder must not enqueue unbounded stale images.

## Files

- Modify `CMakeLists.txt` to link Qt Concurrent to `AuthQt` on desktop and Android.
- Modify `ui/QRSyncTab.h` for watcher, decode cadence, and scan generation state.
- Modify `ui/QRSyncTab.cpp` to schedule asynchronous decodes, update preview separately, handle stale results, and render a bounded centered QR card.
- Modify `docs/superpowers/specs/2026-10-25-qr-scanner-performance-design.md` only if implementation decisions materially change.

### Task 1: Decouple camera preview and QR decoding

**Interfaces:** `processCameraFrame(const QVideoFrame&)` remains the frame entry point. Add one child `QFutureWatcher<QByteArray>` and an asynchronous QR decode helper that accepts an owned `QImage` and returns decoded bytes (empty when no QR is found). The helper must not capture `QRSyncTab`.

- [x] Add Qt6 Concurrent to both Qt component lists and link `Qt6::Concurrent` to `AuthQt` for desktop and Android.
- [x] Add a decode watcher, `decode_pending_`, scan generation token, and separate preview/decode elapsed timers to `QRSyncTab`.
- [x] Update preview at most every 80 ms, without tying preview updates to QR decode frequency.
- [x] Submit a decode no more often than every 150 ms and only if no decode is pending. Keep one frame in flight; never queue stale frames.
- [x] Prefer the rear camera and choose its largest supported format between 640×360 and 1280×720 to bound conversion/decode work while retaining QR detail; use the device default when no supported format fits.
- [x] Convert the owned image to grayscale in the worker and decode with QR-only fast options. Retain rotation detection; use thorough ZXing options periodically as a fallback.
- [x] On watcher completion, read the result on the UI thread and call the existing envelope/protocol validation only if the scanner is active and the result generation matches.
- [x] Increment the generation and clear the active scan state when stopping the camera, cancelling, expiring, or restarting; a running worker may finish but its result is ignored.
- [x] Build `AuthQt` on desktop and Android to verify the concurrency API and Qt target linkage.

### Task 2: Bound and center the Old Device QR

**Interfaces:** Keep `renderQRBitmap(const std::vector<uint8_t>&)` as the renderer entry point.

- [x] Place `qr_label_` inside a centered card on `waiting_qr_page_`, with a 300×300 logical-pixel square QR area and surrounding margin.
- [x] Render the QR matrix at the display area size instead of generating a 2048×2048 pixmap.
- [x] Add vertical stretch around the content so the QR and controls stay grouped and centered without expanding the QR to fill the page.
- [x] Confirm desktop `AuthQt` builds and inspect the final diff; verify the Android target compiles as part of the same build.

## Verification

- Build desktop `AuthQt` and Android `AuthQt_make_apk`.
- Do not run the test suite for this change unless requested.
- Physical camera scan responsiveness still requires a device check; report that limitation clearly.
