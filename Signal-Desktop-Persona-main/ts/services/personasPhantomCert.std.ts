// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo: the phantom sender's identity, and the ONE certificate this member
// accepts for it.
//
// Lives apart from personasPhantom so MessageReceiver can check incoming phantom
// messages without importing the phantom module's stores.
//
// Every member must use byte-identical phantom certificate bytes: certificate
// signatures are randomized, so a different certificate would mark its holder's posts.
// The receiver therefore drops any phantom message whose certificate is not exactly the
// one in our bundle. A distributor who handed one member a different certificate (to
// tag them) is caught here instead of succeeding silently.

export const PHANTOM_SENDER_ACI = '9f9f9f9f-0000-4000-8000-00000000face';

let expected: Uint8Array<ArrayBuffer> | undefined;

export function setExpectedPhantomCertificate(
  bytes: Uint8Array<ArrayBuffer>
): void {
  expected = bytes;
}

// undefined until this member holds a bundle; a phantom message before then is dropped.
export function getExpectedPhantomCertificate():
  | Uint8Array<ArrayBuffer>
  | undefined {
  return expected;
}
