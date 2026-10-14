// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// These pin the badge exclusivity rule, which is MIRRORED from the circuit
// (`assign_badge1 = is_badge1 & !student_exists`, and vice versa; Industry
// unconditional). The circuit silently declines a conflicting assignment rather than
// rejecting it, so a drift between these tests and the circuit would present as "the
// admin approved my badge and I never got it", with nothing in any log.

import { assert } from 'chai';

import {
  BADGE_CATALOGUE,
  badgeBlockedReason,
  badgeNameForSlot,
  badgeSlotForName,
  badgeSlotFromLogBody,
  requestableBadges,
} from '../../services/personasBadgeRules.std.ts';

describe('persona badge rules', () => {
  it('knows exactly the three badges the circuit knows', () => {
    // A fourth would need a circuit change and a keygen, so this list is not free to
    // grow — see PERSONAS_ZK_WORKPLAN.md step 4.
    assert.deepEqual(
      BADGE_CATALOGUE.map(b => b.name),
      ['Faculty', 'Student', 'Industry']
    );
    assert.deepEqual(
      BADGE_CATALOGUE.map(b => b.slot),
      [1, 2, 3]
    );
  });

  it('maps names and slots both ways', () => {
    assert.strictEqual(badgeNameForSlot(2), 'Student');
    assert.strictEqual(badgeSlotForName('Industry'), 3);
    assert.strictEqual(badgeSlotForName('Nonsense'), undefined);
  });

  describe('exclusivity', () => {
    it('blocks Faculty for a Student holder, and the reverse', () => {
      const facultyReason = badgeBlockedReason('Faculty', ['Student']);
      assert.isDefined(facultyReason);
      assert.include(facultyReason as string, 'silently have no effect');

      assert.isDefined(badgeBlockedReason('Student', ['Faculty']));
    });

    it('allows Industry alongside either', () => {
      assert.isUndefined(badgeBlockedReason('Industry', ['Faculty']));
      assert.isUndefined(badgeBlockedReason('Industry', ['Student']));
    });

    it('allows Faculty or Student alongside Industry', () => {
      assert.isUndefined(badgeBlockedReason('Faculty', ['Industry']));
      assert.isUndefined(badgeBlockedReason('Student', ['Industry']));
    });

    it('blocks a badge already held', () => {
      const reason = badgeBlockedReason('Industry', ['Industry']);
      assert.isDefined(reason);
      assert.include(reason as string, 'already hold');
    });

    it('allows anything when nothing is held', () => {
      for (const { name } of BADGE_CATALOGUE) {
        assert.isUndefined(badgeBlockedReason(name, []));
      }
    });
  });

  describe('badgeSlotFromLogBody', () => {
    // These two strings are written by `replica/mod.rs`. If its format changes, a badge
    // request stops rendering as a notification and falls back to showing its internal
    // body text as somebody's chat message — so pin both shapes.
    it('reads the slot out of a request body', () => {
      assert.strictEqual(badgeSlotFromLogBody('requested badge slot 1'), 1);
    });

    it('reads the slot out of an approval body, which does not end with it', () => {
      // THE TRAP. Taking the last word here yields the target's hex, not the slot.
      assert.strictEqual(
        badgeSlotFromLogBody('approved badge slot 2 for 9f3a1c7d'),
        2
      );
    });

    it('refuses a slot outside the catalogue', () => {
      // A fourth badge needs a circuit change; silently accepting slot 4 would show an
      // admin a grant the circuit cannot make.
      assert.isUndefined(badgeSlotFromLogBody('requested badge slot 4'));
      assert.isUndefined(badgeSlotFromLogBody('requested badge slot 0'));
    });

    it('refuses a body that is not about a badge', () => {
      assert.isUndefined(badgeSlotFromLogBody('hello everyone'));
      assert.isUndefined(badgeSlotFromLogBody(''));
    });
  });

  describe('requestableBadges', () => {
    it('returns all three, annotating only the blocked ones', () => {
      const forStudent = requestableBadges(['Student']);
      assert.lengthOf(forStudent, 3);
      // Looked up explicitly rather than through an index signature, so a missing
      // entry fails as "not found" instead of as a confusing undefined-property error.
      const reasonFor = (name: string) =>
        forStudent.find(b => b.name === name)?.blockedReason;
      assert.isDefined(reasonFor('Faculty'), 'Faculty conflicts with Student');
      assert.isDefined(reasonFor('Student'), 'Student is already held');
      assert.isUndefined(reasonFor('Industry'), 'Industry is free');
    });

    it('permits the two legal pairs', () => {
      // The combinations the circuit actually allows: Industry+Faculty, Industry+Student.
      for (const held of [
        ['Industry', 'Faculty'],
        ['Industry', 'Student'],
      ]) {
        for (const { name, blockedReason } of requestableBadges(held)) {
          if (held.includes(name)) {
            assert.isDefined(blockedReason, `${name} already held`);
          }
        }
      }
    });
  });
});
