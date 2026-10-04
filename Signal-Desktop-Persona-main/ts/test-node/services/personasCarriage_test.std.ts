// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo: tests for the carriage convention — the pure, engine-free layer that
// decides how a CryptoPersonas record is packed into a message body and, crucially,
// how the SEND path tells a post apart from everything else.
//
// This is the one piece of the persona stack that is worth unit-testing in isolation,
// and it is worth it because a mistake here is a silent de-anonymisation rather than a
// crash: `isPersonaPhantomBody` is what routes a message onto the shared phantom
// identity. If it ever returned false for a real post, poll or ballot, that record
// would go out attributably under the author's own account and nothing would look
// broken.
//
// (The engine itself is a native darwin-arm64 addon with a ~51MB proving-key bundle;
// its own convergence/ban behaviour is covered by packages/personas-engine/test/
// converge.mjs, which needs that binary.)

import { assert } from 'chai';

import {
  PERSONAS_MARKER,
  PERSONAS_POST_MARKER,
  PERSONAS_POLL_MARKER,
  PERSONAS_VOTE_MARKER,
  PERSONAS_RATE_MARKER,
  PERSONAS_TOPIC_MARKER,
  encodeRecordBody,
  encodePostBody,
  encodePollBody,
  decodeRecordBody,
  decodePollDescriptor,
  encodeVoteBody,
  encodeRateBody,
  encodeTopicAnnouncement,
  decodeTopicAnnouncement,
  isPersonaPhantomBody,
  decodePostBadge,
  type PersonaPollDescriptor,
} from '../../services/personasCarriage.std.ts';

const RECORD = Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x00, 0x7f]);

describe('personasCarriage', () => {
  describe('round trips', () => {
    it('recovers the record bytes from an attributable body', () => {
      const body = encodeRecordBody(RECORD);
      assert.isTrue(body.startsWith(PERSONAS_MARKER));
      assert.deepEqual(decodeRecordBody(body), RECORD);
    });

    it('recovers the record bytes from a post body', () => {
      const body = encodePostBody(RECORD);
      assert.isTrue(body.startsWith(PERSONAS_POST_MARKER));
      assert.deepEqual(decodeRecordBody(body), RECORD);
    });

    it('recovers the record bytes from a poll body', () => {
      const descriptor: PersonaPollDescriptor = {
        question: 'Revoke ~quiet-otter?',
        options: ['Ban', 'Keep'],
        kind: 'ban',
      };
      const body = encodePollBody(RECORD, descriptor);
      assert.isTrue(body.startsWith(PERSONAS_POLL_MARKER));
      // The record must survive intact even though the body also carries display data.
      assert.deepEqual(decodeRecordBody(body), RECORD);
      assert.deepEqual(decodePollDescriptor(body), descriptor);
    });

    it('preserves poll option order, which decides what a ban vote means', () => {
      // The engine settles a ban from the option INDEX, so a descriptor that
      // reordered the labels in transit would invert the outcome.
      const descriptor: PersonaPollDescriptor = {
        question: 'q',
        options: ['Ban', 'Keep', 'Abstain'],
        kind: 'ban',
      };
      const decoded = decodePollDescriptor(encodePollBody(RECORD, descriptor));
      assert.deepEqual(decoded?.options, ['Ban', 'Keep', 'Abstain']);
    });
  });

  describe('decodeRecordBody', () => {
    it('returns undefined for ordinary chatter', () => {
      assert.isUndefined(decodeRecordBody('hello there'));
      assert.isUndefined(decodeRecordBody(''));
      assert.isUndefined(decodeRecordBody(undefined));
      assert.isUndefined(decodeRecordBody(null));
    });

    it('does not treat a marker appearing mid-body as a record', () => {
      assert.isUndefined(decodeRecordBody(`look at this ${PERSONAS_MARKER}abc`));
    });

    it('returns undefined for a poll body with malformed JSON', () => {
      const bogus =
        PERSONAS_POLL_MARKER + Buffer.from('{not json', 'utf8').toString('base64');
      assert.isUndefined(decodeRecordBody(bogus));
      assert.isUndefined(decodePollDescriptor(bogus));
    });
  });

  describe('isPersonaPhantomBody', () => {
    // This is the phantom-routing gate. Getting it wrong in either direction is a
    // correctness bug with privacy consequences, so both directions are asserted.
    const poll = () =>
      encodePollBody(RECORD, {
        question: 'q',
        options: ['a', 'b'],
        kind: 'standard',
      });

    it('is true for the records whose author must be unlinkable', () => {
      // Posts, polls and ballots: an attributable poll would expose who called for a
      // revocation, and an attributable ballot would defeat an anonymous poll.
      assert.isTrue(isPersonaPhantomBody(encodePostBody(RECORD)));
      assert.isTrue(isPersonaPhantomBody(poll()));
      assert.isTrue(isPersonaPhantomBody(encodeVoteBody(RECORD)));
      // A rating is pseudonymous in-circuit too (context = target.context()), so an
      // attributable envelope would name the rater outright.
      assert.isTrue(isPersonaPhantomBody(encodeRateBody(RECORD)));
    });

    it('is false for attributable records and plain chatter', () => {
      // Joins and scans stay attributable: one membership per real account is what
      // makes a ban impossible to evade by re-joining.
      assert.isFalse(isPersonaPhantomBody(encodeRecordBody(RECORD)));
      assert.isFalse(isPersonaPhantomBody('just a message'));
      assert.isFalse(isPersonaPhantomBody(undefined));
      assert.isFalse(isPersonaPhantomBody(null));
    });
  });

  describe('topic announcements', () => {
    it('round trips a name and context', () => {
      const announcement = { name: 'Union', context: 123456789 };
      const body = encodeTopicAnnouncement(announcement);
      assert.isTrue(body.startsWith(PERSONAS_TOPIC_MARKER));
      assert.deepEqual(decodeTopicAnnouncement(body), announcement);
    });

    it('is not mistaken for a ZK record', () => {
      // An announcement carries no proof; handing it to the engine would be rejected,
      // so decodeRecordBody must not claim it.
      const body = encodeTopicAnnouncement({ name: 'Union', context: 7 });
      assert.isUndefined(decodeRecordBody(body));
      assert.isFalse(isPersonaPhantomBody(body));
    });

    it('returns undefined for other bodies', () => {
      assert.isUndefined(decodeTopicAnnouncement(encodePostBody(RECORD)));
      assert.isUndefined(decodeTopicAnnouncement('hello'));
      assert.isUndefined(decodeTopicAnnouncement(undefined));
    });
  });

  describe('marker distinctness', () => {
    it('uses six distinct, equal-length markers', () => {
      const markers = [
        PERSONAS_MARKER,
        PERSONAS_POST_MARKER,
        PERSONAS_POLL_MARKER,
        PERSONAS_VOTE_MARKER,
        PERSONAS_RATE_MARKER,
        PERSONAS_TOPIC_MARKER,
      ];
      assert.equal(new Set(markers).size, 6);
      // Equal length keeps the `body.slice(marker.length)` decode uniform, and means
      // no marker can be a prefix of another.
      assert.equal(new Set(markers.map(m => m.length)).size, 1);
    });
  });
});

describe('post badge claims', () => {
  const record = Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x00, 0x7b, 0x22]);

  it('encodes a plain post exactly as before badges existed', () => {
    // Backward compatibility is the whole point of the two-shape design: an instance
    // that never sets a badge must produce byte-identical bodies to the old build.
    assert.strictEqual(
      encodePostBody(record),
      `PZP2:${record.toString('base64')}`
    );
  });

  it('round-trips the record through a badged post', () => {
    const body = encodePostBody(record, 'Faculty');
    assert.deepStrictEqual(decodeRecordBody(body), record);
    assert.strictEqual(decodePostBadge(body), 'Faculty');
  });

  it('round-trips the record through a plain post', () => {
    const body = encodePostBody(record);
    assert.deepStrictEqual(decodeRecordBody(body), record);
    assert.strictEqual(decodePostBadge(body), undefined);
  });

  it('still routes a badged post over the phantom identity', () => {
    // A badge must not change the anonymity routing: a badged post is still a post.
    assert.ok(isPersonaPhantomBody(encodePostBody(record, 'Student')));
  });

  it('treats a malformed envelope as a plain post rather than throwing', () => {
    const body = `PZP2:${Buffer.from('{"nope":1}', 'utf8').toString('base64')}`;
    assert.strictEqual(decodePostBadge(body), undefined);
    assert.doesNotThrow(() => decodeRecordBody(body));
  });

  it('ignores a non-string badge from a hostile peer', () => {
    const envelope = JSON.stringify({ r: record.toString('base64'), b: 42 });
    const body = `PZP2:${Buffer.from(envelope, 'utf8').toString('base64')}`;
    assert.strictEqual(decodePostBadge(body), undefined);
    assert.deepStrictEqual(decodeRecordBody(body), record);
  });
});
