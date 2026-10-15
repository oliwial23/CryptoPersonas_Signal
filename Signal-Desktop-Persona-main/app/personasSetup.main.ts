// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas build: the first-launch window where a tester picks the name other testers see.
//
// Shown once, before the main window, because the name is needed before registration:
// it becomes the Signal profile name and the member-directory entry.
//
// Deliberately minimal and inert: an isolated session (Signal's protocol filters guard the
// default session and are not installed yet anyway), no preload, no Node, sandboxed. The
// page reports the chosen name by setting its title to `personas-name:<encoded name>`,
// which the main process reads from `page-title-updated` — no IPC channel and no
// navigation to police. Closing the window keeps the suggested name.

import { BrowserWindow } from 'electron';

const TITLE_PREFIX = 'personas-name:';
const MAX_NAME_LENGTH = 40;

// Trim, collapse whitespace, drop control characters, and cap the length. Returns
// undefined when nothing usable is left.
export function sanitizeDisplayName(raw: string): string | undefined {
  const cleaned = raw
    // Whitespace first (so a line break becomes a space, not nothing), then drop the
    // remaining control and bidi-override characters, which can disguise a name.
    .replace(/\s+/g, ' ')
    .replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, '')
    .replace(/ {2,}/g, ' ')
    .trim()
    .slice(0, MAX_NAME_LENGTH)
    .trim();
  return cleaned ? cleaned : undefined;
}

function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
}

function pageHtml(suggestion: string): string {
  const value = escapeHtml(suggestion);
  return `<!doctype html>
<html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>Signal Personas</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 14px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 28px; }
  h1 { font-size: 18px; margin: 0 0 8px; }
  p { margin: 0 0 14px; opacity: .8; }
  input { width: 100%; box-sizing: border-box; font: inherit; padding: 8px 10px; border-radius: 6px;
          border: 1px solid #8888; background: transparent; color: inherit; }
  button { margin-top: 16px; font: inherit; padding: 7px 16px; border-radius: 6px; border: 0;
           background: #2c6bed; color: #fff; cursor: pointer; float: right; }
  button:disabled { opacity: .5; cursor: default; }
</style></head>
<body>
  <h1>Choose your display name</h1>
  <p>Other testers see this name next to your account, for example in the group member
     list. Your persona posts stay anonymous; this name is not attached to them.
     It doesn't need to be your real name.</p>
  <form id="f">
    <input id="name" maxlength="${MAX_NAME_LENGTH}" value="${value}" autofocus required>
    <button id="go" type="submit">Continue</button>
  </form>
  <script>
    const input = document.getElementById('name');
    const go = document.getElementById('go');
    input.select();
    input.addEventListener('input', () => { go.disabled = !input.value.trim(); });
    document.getElementById('f').addEventListener('submit', event => {
      event.preventDefault();
      const name = input.value.trim();
      if (name) {
        go.disabled = true;
        document.title = ${JSON.stringify(TITLE_PREFIX)} + encodeURIComponent(name);
      }
    });
  </script>
</body></html>`;
}

// Ask once for a display name. Resolves to the sanitized choice, or `suggestion` if the
// window is closed without one.
export function promptForDisplayName(suggestion: string): Promise<string> {
  return new Promise(resolve => {
    const window = new BrowserWindow({
      width: 460,
      height: 290,
      resizable: false,
      minimizable: false,
      maximizable: false,
      fullscreenable: false,
      title: 'Signal Personas',
      show: false,
      webPreferences: {
        partition: 'personas-setup',
        sandbox: true,
        contextIsolation: true,
        nodeIntegration: false,
        spellcheck: false,
      },
    });

    let settled = false;
    const finish = (name: string) => {
      if (settled) {
        return;
      }
      settled = true;
      resolve(name);
      if (!window.isDestroyed()) {
        window.close();
      }
    };

    window.webContents.on('page-title-updated', (_event, title) => {
      if (!title.startsWith(TITLE_PREFIX)) {
        return;
      }
      let decoded = '';
      try {
        decoded = decodeURIComponent(title.slice(TITLE_PREFIX.length));
      } catch {
        // Malformed escape: fall through to the suggestion.
      }
      finish(sanitizeDisplayName(decoded) ?? suggestion);
    });
    window.on('closed', () => finish(suggestion));
    window.once('ready-to-show', () => window.show());

    void window.loadURL(
      `data:text/html;charset=utf-8,${encodeURIComponent(pageHtml(suggestion))}`
    );
  });
}
