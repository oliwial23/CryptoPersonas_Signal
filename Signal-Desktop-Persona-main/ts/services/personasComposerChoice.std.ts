// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Turning the composer's persona dropdown value into a PersonaChoice.
//
// Lives in a `.std` module rather than inside CompositionArea because it is the rule
// that decides WHICH IDENTITY a message is sent under, and that deserves tests. It was
// previously a private function in a `.dom` component, so it could not be tested at
// all — and it carried a bug that silently dropped the context from every post made as
// anything other than an explicit `rate:` selection.

import type { PersonaChoice } from './personasCarriage.std.ts';

/** Rate-limited pseudonym used when a context is selected but no index was picked. */
export const DEFAULT_RATE_INDEX = 0; // shown as "#1" in the UI

/**
 * Dropdown value -> persona choice.
 *
 * Values: 'off' | 'anon' | 'pseudo:<nonce>' | 'rate:<index>'.
 *
 * THE CONTEXT RULE. A selected context forces a rate-limited pseudonym for that
 * context. This is correctness, not convenience: in the protocol a context only means
 * something for a rate-limited pseudonym, because the rate limit binds the pseudonym to
 * the context in-circuit. An anonymous or unlimited-pseudonym post carries a context
 * LABEL with nothing in the proof tying it there, so "posting in a context" as anything
 * else is a claim the protocol does not back.
 *
 * 'off' is exempt. It means an ordinary attributable message, and a selected context
 * must never silently turn one of those into an anonymous post.
 */
export function personaValueToChoice(
  value: string,
  topicContext: number | undefined
): PersonaChoice | undefined {
  if (value === 'off') {
    return undefined;
  }

  if (topicContext != null) {
    const parsed = value.startsWith('rate:')
      ? Number(value.slice('rate:'.length))
      : DEFAULT_RATE_INDEX;
    return {
      kind: 'rate',
      context: topicContext,
      // Guard the parse: a malformed value must not become NaN and travel into a
      // proof's public inputs, where it would fail far from its cause.
      index: Number.isInteger(parsed) && parsed >= 0 ? parsed : DEFAULT_RATE_INDEX,
    };
  }

  if (value.startsWith('pseudo:')) {
    // The nonce IS the identity: the same nonce always derives the same petname, so
    // selecting one is what lets a member post twice as the same persona.
    const nonce = Number(value.slice('pseudo:'.length));
    return Number.isFinite(nonce) ? { kind: 'pseudo', nonce } : undefined;
  }
  if (value === 'anon') {
    return { kind: 'anon' };
  }
  // `rate:` with no context selected is not satisfiable — there is no context for the
  // rate limit to bind to — so refuse rather than quietly downgrade to an unlimited
  // pseudonym, which would be a weaker identity than the user asked for.
  return undefined;
}
