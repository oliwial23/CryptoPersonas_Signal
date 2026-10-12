// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// This function decides WHICH IDENTITY a message is sent under, so every branch is
// pinned. It previously lived inside a .dom component where it could not be tested,
// and it shipped a bug that dropped the context from every post not made as an
// explicit `rate:` selection — which made the context label vanish from the UI with no
// error anywhere.

import { assert } from 'chai';

import {
  DEFAULT_RATE_INDEX,
  personaValueToChoice,
} from '../../services/personasComposerChoice.std.ts';

const CONTEXT = 987654;

describe('personaValueToChoice', () => {
  describe("'off' is never overridden", () => {
    it('returns undefined even when a context is selected', () => {
      // The safety-critical case: a selected context must NOT turn an ordinary
      // attributable message into an anonymous one.
      assert.isUndefined(personaValueToChoice('off', CONTEXT));
      assert.isUndefined(personaValueToChoice('off', undefined));
    });
  });

  describe('a selected context forces a rate-limited pseudonym', () => {
    it('coerces anon to rate-limited #1', () => {
      assert.deepEqual(personaValueToChoice('anon', CONTEXT), {
        kind: 'rate',
        context: CONTEXT,
        index: DEFAULT_RATE_INDEX,
      });
    });

    it('coerces an unlimited pseudonym to rate-limited #1', () => {
      assert.deepEqual(personaValueToChoice('pseudo:12345', CONTEXT), {
        kind: 'rate',
        context: CONTEXT,
        index: DEFAULT_RATE_INDEX,
      });
    });

    it('keeps an explicitly chosen index', () => {
      assert.deepEqual(personaValueToChoice('rate:2', CONTEXT), {
        kind: 'rate',
        context: CONTEXT,
        index: 2,
      });
    });

    it('falls back to #1 for a malformed index rather than emitting NaN', () => {
      // NaN would travel into the proof's public inputs and fail far from its cause.
      for (const bad of ['rate:', 'rate:abc', 'rate:-1', 'rate:1.5']) {
        assert.deepEqual(
          personaValueToChoice(bad, CONTEXT),
          { kind: 'rate', context: CONTEXT, index: DEFAULT_RATE_INDEX },
          `expected ${bad} to fall back`
        );
      }
    });
  });

  describe('with no context selected', () => {
    it('passes anon through', () => {
      assert.deepEqual(personaValueToChoice('anon', undefined), {
        kind: 'anon',
      });
    });

    it('passes an unlimited pseudonym through with its nonce', () => {
      assert.deepEqual(personaValueToChoice('pseudo:12345', undefined), {
        kind: 'pseudo',
        nonce: 12345,
      });
    });

    it('refuses a rate-limited selection, rather than downgrading it', () => {
      // There is no context for the rate limit to bind to. Silently returning an
      // unlimited pseudonym would give a weaker identity than the user asked for.
      assert.isUndefined(personaValueToChoice('rate:0', undefined));
      assert.isUndefined(personaValueToChoice('rate:3', undefined));
    });

    it('returns undefined for an unrecognized value', () => {
      assert.isUndefined(personaValueToChoice('', undefined));
      assert.isUndefined(personaValueToChoice('nonsense', undefined));
    });
  });

  it('context 0 is a real context, not absent', () => {
    // A context number of 0 is valid. Testing truthiness instead of null would treat
    // it as "no context" and silently drop the binding.
    assert.deepEqual(personaValueToChoice('anon', 0), {
      kind: 'rate',
      context: 0,
      index: DEFAULT_RATE_INDEX,
    });
  });
});
