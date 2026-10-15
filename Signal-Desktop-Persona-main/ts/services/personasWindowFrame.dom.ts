// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo: a colored frame around the window and the member's name at the top, so a
// tester running their main member and two extra members side by side can tell at a
// glance which window is which (the window title also carries the name, but it is easy
// to miss). Purely visual: it never takes a click.
//
// The color follows the member's slot — main, extra 1, extra 2 (app/user_config,
// PERSONAS_PROFILE) — so it stays the same across restarts; any other member (a browser
// member, a hand-named profile) gets one picked from its name.

const SLOT_COLORS: Record<string, string> = {
  '': '#16a34a', // main member: green
  'extra-1': '#ea580c', // orange
  'extra-2': '#9333ea', // purple
};
const OTHER_COLORS = ['#0891b2', '#db2777', '#ca8a04', '#2563eb'];

function colorFor(profile: string, name: string): string {
  const slot = SLOT_COLORS[profile];
  if (slot) {
    return slot;
  }
  let hash = 0;
  for (const char of `${profile}:${name}`) {
    hash = (hash * 31 + (char.codePointAt(0) ?? 0)) % 2_147_483_647;
  }
  return OTHER_COLORS[hash % OTHER_COLORS.length] ?? '#2563eb';
}

export function installPersonasWindowFrame({
  name,
  profile,
}: {
  name: string;
  profile: string;
}): void {
  const color = colorFor(profile, name);

  const install = () => {
    const frame = document.createElement('div');
    frame.setAttribute('aria-hidden', 'true');
    Object.assign(frame.style, {
      position: 'fixed',
      inset: '0',
      border: `4px solid ${color}`,
      pointerEvents: 'none',
      zIndex: '2147483647',
    });

    const label = document.createElement('div');
    label.setAttribute('aria-hidden', 'true');
    label.textContent = name;
    Object.assign(label.style, {
      position: 'fixed',
      top: '0',
      left: '50%',
      transform: 'translateX(-50%)',
      maxWidth: '40vw',
      overflow: 'hidden',
      textOverflow: 'ellipsis',
      whiteSpace: 'nowrap',
      padding: '1px 12px 3px',
      borderRadius: '0 0 8px 8px',
      background: color,
      color: '#ffffff',
      font: '600 12px/16px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
      pointerEvents: 'none',
      zIndex: '2147483647',
    });

    document.body.append(frame, label);
  };

  if (document.body) {
    install();
  } else {
    window.addEventListener('DOMContentLoaded', install, { once: true });
  }
}
