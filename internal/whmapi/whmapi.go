// Package whmapi implements the WHM API 1 (json-api) transport, envelope and
// authentication contract observed on the licensed cPanel & WHM 11.138.0.11
// reference host (docs/reference/whm-cpanel-138-first-observation.md,
// whm-cpanel-138-envelopes-and-layout.md, whm-cpanel-138-lifecycle-capture.md).
//
// This is a clean-room compatibility surface: behavior is re-implemented from
// documented APIs and observed wire envelopes. No proprietary cPanel code is
// used. The surface fails closed: without a Backend and Authenticator it
// serves nothing, and unknown functions receive the exact observed
// unknown-app error rather than a fabricated success.
//
// FROZEN (docs/PRODUCT-PLAN.md, "cPanel compatibility par do baatein"): the
// product no longer targets zero-edit cPanel compatibility. Bug and security
// fixes are welcome here. New functions, new parity work and new callers are
// not: WHMCS provisioning moves to Sifruno's own module on the native API.
package whmapi
