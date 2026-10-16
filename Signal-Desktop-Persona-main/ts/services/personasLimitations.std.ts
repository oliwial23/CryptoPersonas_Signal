// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo — short tips for the person USING the app, shown in the status panel.
//
// Pure data, in a `.std` module on purpose: the status panel is a renderer component
// and must not import a `.preload` one, or the native ZK addon gets dragged into the
// renderer bundle. One line each; only what changes how someone demos it.

export const PERSONA_TIPS: ReadonlyArray<string> = [
  'Each group has its own personas; they cannot be linked across groups. This app uses personas in one group for now.',
  'Someone added later needs an admin\u2019s app open to get started.',
  'If two people post at the same moment, one post can be lost \u2014 send it again.',
  'An admin\u2019s permanent ban takes effect within seconds; the group sees which admin issued it.',
];
