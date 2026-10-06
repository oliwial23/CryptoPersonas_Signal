// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo — WHICH ACCOUNT IS THIS WINDOW?
//
// With three or more instances open side by side, every window is a pixel-identical copy
// of Signal Desktop. Telling alice from bob from carol meant reading the conversation
// list and inferring it, which is slow, and during a live demo it is the single easiest
// thing to get wrong in front of an audience — you rate from the wrong window, or claim
// a post was anonymous while pointing at the author's own instance.
//
// So: a persistent strip at the top of the window carrying the instance name, with a
// per-instance accent colour. Colour alone would be a bad idea (colour-blind viewers,
// projectors that shift hues, screenshots in papers that end up greyscale), so the NAME
// is always present and the colour is redundant reinforcement rather than the signal.
//
// Deliberately NOT a Signal-native chrome element: this is demo scaffolding and should
// look like it, so nobody mistakes it for a real Signal feature in a screenshot.

import type { JSX } from 'react';


// A fixed palette keyed by instance name, so alice is always the same colour in every
// screenshot and every run — stable identity matters more than aesthetics here.
//
// Chosen to stay distinguishable under the common forms of colour-blindness (the pairs
// differ in lightness as well as hue) and to survive projector washout.
const ACCENT: Record<string, { bg: string; fg: string }> = {
  alice: { bg: 'rgb(30, 90, 168)', fg: 'white' }, // blue
  bob: { bg: 'rgb(150, 70, 10)', fg: 'white' }, // orange-brown
  carol: { bg: 'rgb(90, 40, 130)', fg: 'white' }, // purple
  dave: { bg: 'rgb(20, 110, 95)', fg: 'white' }, // teal
  erin: { bg: 'rgb(140, 30, 70)', fg: 'white' }, // magenta
};

// Anything not in the table gets a deterministic colour from its name, so an ad-hoc
// instance (personas-run.sh frank +1202...) is still visually distinct rather than
// falling back to a shared default that defeats the purpose.
function accentFor(instance: string): { bg: string; fg: string } {
  const known = ACCENT[instance.toLowerCase()];
  if (known) {
    return known;
  }
  let hash = 0;
  for (let i = 0; i < instance.length; i += 1) {
    hash = (hash * 31 + instance.charCodeAt(i)) % 360;
  }
  return { bg: `hsl(${hash}, 55%, 32%)`, fg: 'white' };
}

export function PersonaAccountBanner({
  instance,
}: Readonly<{ instance: string | undefined }>): JSX.Element | null {
  // Absent in a normal build (no NODE_APP_INSTANCE), so this renders nothing and the
  // app looks untouched outside the demo.
  if (!instance) {
    return null;
  }

  const { bg, fg } = accentFor(instance);

  // TWO cues, both fixed-position and both `pointer-events: none`:
  //
  //   * a 3px accent frame around the whole window — the thing that actually works when
  //     windows OVERLAP, because an edge stays visible when the centre is covered;
  //   * a name pill at top centre, for when a window is focused and you need certainty.
  //
  // Fixed rather than in the layout flow so neither can shift Signal's own geometry, and
  // non-interactive so they cannot swallow a click. Centred rather than full-width
  // because a full-width strip would sit on top of the macOS traffic lights (the window
  // is titleBarStyle: 'hidden', so the top-left is real window chrome).
  return (
    <>
      <div
        aria-hidden="true"
        style={{
          position: 'fixed',
          inset: 0,
          border: `3px solid ${bg}`,
          borderRadius: 2,
          pointerEvents: 'none',
          zIndex: 9999,
        }}
      />
      <div
        style={{
          position: 'fixed',
          top: 0,
          left: '50%',
          transform: 'translateX(-50%)',
          backgroundColor: bg,
          color: fg,
          padding: '1px 10px 2px',
          borderBottomLeftRadius: 6,
          borderBottomRightRadius: 6,
          fontSize: 11,
          fontWeight: 600,
          letterSpacing: '0.08em',
          pointerEvents: 'none',
          zIndex: 10000,
        }}
        aria-label={`This window is the ${instance} account`}
      >
        {instance.toUpperCase()}
      </div>
    </>
  );
}
