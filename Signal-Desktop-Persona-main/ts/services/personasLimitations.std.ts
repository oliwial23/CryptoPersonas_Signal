// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo — the limitations this build genuinely has.
//
// Pure data, in a `.std` module on purpose: the status panel is a renderer component
// and must not import a `.preload` one, or the native ZK addon gets dragged into the
// renderer bundle (the same reason personasCarriage.std.ts exists).
//
// Each entry is a real, current gap — not a disclaimer. They sit next to the green
// rows in the status panel so nobody can read the good news without the caveats. If
// one of these gets fixed, delete the line rather than softening it.

export const KNOWN_LIMITATIONS: ReadonlyArray<{
  title: string;
  detail: string;
}> = [
  {
    title: 'Self-rating is undetectable by the protocol',
    detail:
      'A member can rate their own persona post and inflate their own reputation, and no replica can tell. The tally dedupes one rating per pseudonym per target, but the author\u2019s pseudonym is H(sk, post context) while the rater\u2019s is H(sk, target context), so the two look unrelated \u2014 which is exactly the unlinkability the scheme is built on. This client refuses to offer self-rating, but that is a UI choice, not enforcement: a modified client can still do it. Closing it properly needs the circuit to prove rater \u2260 author without revealing either.',
  },
  {
    title: 'Authorship is proved, but it is permanent and public',
    detail:
      'Claiming authorship is now a real zero-knowledge proof: authorship_pred binds both pseudonyms to one secret key, recipients verify the Groth16 proof before rendering, and a proof that fails verification is dropped rather than shown. The two names you see are derived from the proof\u2019s own public inputs, not from the message, so a valid proof cannot be displayed next to someone else\u2019s persona names. What remains is not a soundness gap but a consequence: a claim cannot be retracted, and it permanently links those two personas for everyone who saw it \u2014 including anyone who later learns something about either one.',
  },
  {
    title: 'Badge approvals are not tied to an admin',
    detail:
      'Holding a badge is proved in zero knowledge (\u201cProve badge\u201d), and the proof is checked against this group\u2019s own state, so nobody can fake one. But the APPROVAL that grants it is anonymous: the app only shows Approve to admins, and a modified client could approve its own request. The admin also sees \u201canonymous\u201d rather than who asked. The badge label on an ordinary post is display metadata, not a proof.',
  },
  {
    title: 'Reputation only moves when YOU scan',
    detail:
      'Reputation now works (Engine::get_reputation reads it out of your zk user object). It is your OWN score — nobody can look up anyone else’s, because it lives inside your object rather than on the bulletin. It changes when a scan ABSORBS a rating callback, not when someone rates you: so the sequence is they rate, then you scan. A scan with nothing outstanding correctly changes nothing, and a brand-new member legitimately reads 0, which is indistinguishable on screen from "nobody has rated me yet".',
  },
  {
    title: 'A ban is not immediate',
    detail:
      'A permanent ban is recorded at once, but it bites in two steps: the callback is invoked at the next settlement barrier, and the banned member’s own next scan is what writes the ban into their object and makes their persona proofs unsatisfiable. Until both happen their posts render flagged but still arrive. Making it instant would require linking the pseudonym to the real identity — which would defeat the point of the system.',
  },
  {
    title: 'A permanent ban can still be cancelled by a Keep vote',
    detail:
      'An admin’s "Ban permanently" opens a ban poll and casts the admin’s own Ban ballot, which carries 1-0 at the close barrier — and the poll bubble is hidden, so in practice nobody votes against it. But the mechanism is still a poll: if anyone did cast Keep, the tally would be 1-1, the "yes > no" test would fail, and the ban would not land. A genuinely unilateral ban needs a Record::Ban variant plus an admin key in the replica config so every replica can verify who is entitled to emit one (PERSONAS_ZK_WORKPLAN.md step 3b).',
  },
  {
    title: 'An interrupted scan used to be fatal',
    detail:
      'The callbacks crate ASSERTS that no scan is in progress rather than returning an error, so a half-finished sweep made the next post abort the whole window (exit code 6, no catchable error). The addon now refuses those calls with a real error and the panel shows an "Unfinished scan" banner with the outstanding count. The remedy is to keep pressing Scan now until it clears; the underlying assertion is still there, so this is a guard rather than a fix.',
  },
  {
    title: 'Admin checks are advisory, not enforcement',
    detail:
      "Banning permanently and creating a context are limited to holders of Signal's GroupV2 admin role; REQUESTING a ban poll is open to every member, since it only asks the group. All of these are CLIENT-SIDE gates: persona records are ordinary message bodies the storage-service never inspects, so a modified client ignores them. The gate also costs a little anonymity by inference rather than by data \u2014 a ban poll rides the shared phantom, so no recipient learns who opened it, but if only admins ever ban then an observer who knows the admin set can narrow the opener to it, and with a single admin that identifies them. Real enforcement needs the admin key inside the accept rule (step 3b) or the moderator credential inside the proof, which is what badges are for.",},
  {
    title: 'A member added later trusts an admin\u2019s copy',
    detail:
      'A member added after the group started gets the group\u2019s state from an admin\u2019s app (every record, without the text of old posts and polls) and takes it as it is. A dishonest admin could hand over a doctored copy: the newcomer\u2019s persona posts would then be refused by everyone else, and that admin could recognise them. Existing members are unaffected, since they check every post against their own state. Until a copy arrives the newcomer cannot send persona messages, so an admin\u2019s app has to be open.',
  },
  {
    title: 'Two posts at the same moment can split the group',
    detail:
      'Posts sent within the same few seconds can be built on different views of the group state. One of them is then held back by everyone else, and that member\u2019s later persona posts may stop getting through until they reset.',
  },
  {
    title: 'Personas work in one group per app, for now',
    detail:
      'Each group has its own personas: its own anonymous identity, state, pseudonyms, contexts, badges, reputation and bans, none of it shared with another group, so your personas in one group cannot be linked to another. For now an app takes part in ONE personas group, the first it was given personas in; in any other group the persona menu says so. Using several groups at once is planned.',
  },
  {
    title: 'Scans are not folded',
    detail:
      'Each scan absorbs one waiting item (a rating, a badge, a ban) with one proof, so a backlog takes several proofs, each freezing the window for a few seconds.',
  },
];
