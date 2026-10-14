// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// These guard the "dropped as an empty message" bug, which has been introduced once per
// bodiless persona record type and is silent every time: the sender's own copy is built
// locally and never passes through `isMessageEmpty`, so only the RECIPIENTS lose the
// message. For a badge request, the recipient who loses it is the admin who was supposed
// to approve it.

import { assert } from 'chai';

import {
  PERSONA_BODILESS_FIELDS,
  personaRendersWithoutBody,
} from '../../util/personaRendersWithoutBody.std.ts';

describe('personaRendersWithoutBody', () => {
  it('lists every persona record type that renders without a body', () => {
    // Deliberately exact rather than a length check. A new bodiless record type must
    // fail this test, which is the only reliable way to make someone add it to the
    // list — reviewing a missing `||` in isMessageEmpty has not worked three times now.
    assert.deepEqual(
      [...PERSONA_BODILESS_FIELDS],
      [
        'personaPoll',
        'personaAuthorship',
        'personaBadgeNotice',
        'personaBadgeProof',
      ]
    );
  });

  it('is false for an ordinary message', () => {
    assert.isFalse(personaRendersWithoutBody({}));
  });

  it('is true for each field on its own', () => {
    assert.isTrue(
      personaRendersWithoutBody({
        personaPoll: { question: 'q', options: ['a'], kind: 'standard' },
      })
    );
    assert.isTrue(
      personaRendersWithoutBody({
        personaAuthorship: { first: '~a', second: '~b' },
      })
    );
    assert.isTrue(
      personaRendersWithoutBody({
        personaBadgeNotice: { kind: 'request', eh: 'ab12', slot: 1 },
      })
    );
  });

  it('is true for a badge possession proof', () => {
    assert.isTrue(
      personaRendersWithoutBody({
        personaBadgeProof: { badge: 'Faculty', verified: true },
      })
    );
  });

  it('is true for a badge APPROVAL as well as a request', () => {
    // Both directions render, and an approval that vanished would leave the requester
    // with no indication they have a badge to collect.
    assert.isTrue(
      personaRendersWithoutBody({
        personaBadgeNotice: { kind: 'approve', eh: 'cd34', slot: 3 },
      })
    );
  });

  it('treats slot 0 as present, not as absent', () => {
    // The check is `!= null`, not truthiness. A truthiness check on the OBJECT is fine,
    // but this pins the intent: the presence of the record is what matters, and no
    // falsy-but-present value should read as empty.
    assert.isTrue(
      personaRendersWithoutBody({
        personaBadgeNotice: { kind: 'request', eh: '', slot: 0 },
      })
    );
  });
});
