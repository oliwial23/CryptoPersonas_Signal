// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo: the phantom sender's identity, and the certificates (one per personas
// group) this member accepts for it.
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

// One certificate per personas group this member holds a bundle for.
const expected: Array<Uint8Array<ArrayBuffer>> = [];

export function addExpectedPhantomCertificate(bytes: Uint8Array<ArrayBuffer>): void {
  if (!expected.some(known => equalBytes(known, bytes))) {
    expected.push(bytes);
  }
}

// Whether `bytes` is exactly the certificate of one of our bundles. False before this
// member holds any; such a phantom message is dropped.
export function isExpectedPhantomCertificate(bytes: Uint8Array<ArrayBuffer>): boolean {
  return expected.some(known => equalBytes(known, bytes));
}

export function hasAnyPhantomCertificate(): boolean {
  return expected.length > 0;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}
