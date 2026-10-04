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
    title: 'Authorship claims are unverified assertions',
    detail:
      'Claim authorship sends "these two personas are both me" as a plain statement. Nothing proves it, and anyone can claim any pair of petnames including ones that are not theirs. The real feature is a zero-knowledge proof and is unusually close — authorship_pred exists in personas-core and its proving key already ships — but the serverless Member has no method to build the statement, so there is nothing to verify against. See PERSONAS_SERVERLESS_TODO.md section 1.',
  },
  {
    title: 'Badges are unverified claims, not credentials',
    detail:
      'The badge shown beside a persona is a plain label the sender chose and attached to the message. Nothing checks it, nothing grants it, and any client can claim any badge. The real design proves badge possession in zero knowledge (the circuit exists in personas-core), but the grant flow lives only in the as-a-service client, so the serverless build this app uses has no way to issue or verify one. Treat every badge you see here as decoration.',
  },
  {
    title: 'Reputation is unavailable in this build',
    detail:
      'The native binding that reads your reputation (Engine::get_reputation) compiles but kills the render process at runtime, so it is not in the shipped addon. The status panel shows Unavailable rather than a wrong number. See PERSONAS_DEMO.md section 8.0.',
  },
  {
    title: 'A ban is not immediate',
    detail:
      'A revoked member stops being able to post only at the next key rotation, which is periodic. Until then their posts render flagged but still arrive. Making it instant would require linking the pseudonym to the real identity — which would defeat the point of the system.',
  },
  {
    title: 'Admin checks are advisory, not enforcement',
    detail:
      "Signal's group-admin role is server-enforced for Signal's own group operations, but persona records are ordinary message bodies the server never inspects — so any admin check the client makes can be ignored by a modified client. Attributable actions (creating a topic) are gated as a convenience; anonymous ones are not gated at all, because checking who opened a ban poll would require de-anonymising them. Real admin gating needs the credential to live in the proof — that is what badges are for.",
  },
  {
    title: 'Joining is ungated at the protocol level',
    detail:
      'Signal group membership is genuinely server-enforced — a non-member cannot receive the group messages at all — but nothing in the ZK layer restricts who may join the persona group beyond that.',
  },
  {
    title: 'Protocol state is not persisted',
    detail:
      'The replica lives only in memory. Restarting the app forgets every record — joins, posts, polls and bans — while the Signal chat history survives.',
  },
  {
    title: 'Folded scans drop callbacks of other fold sizes',
    detail:
      'The proving-key cache is single-size today, so a folded scan only absorbs callbacks matching that size.',
  },
];
