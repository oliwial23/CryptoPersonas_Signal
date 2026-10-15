// Copyright 2017 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import { join } from 'node:path';
import { mkdirSync } from 'node:fs';
import { app } from 'electron';

import { start } from './base_config.node.ts';
import config from './config.main.ts';
import * as Errors from '../ts/types/errors.std.ts';
import OS from '../ts/util/os/osMain.node.ts';
import { isPersonasBuild } from './personas.main.ts';

let userData: string | undefined;
// Use separate data directory for benchmarks & development
if (config.has('storagePath')) {
  userData = String(config.get('storagePath'));
} else if (config.has('storageProfile')) {
  userData = join(
    app.getPath('appData'),
    // oxlint-disable-next-line typescript/restrict-template-expressions
    `Signal-${config.get('storageProfile')}`
  );
} else if (isPersonasBuild()) {
  // Its own data folder, so a personas build can never open (or damage) a real Signal
  // Desktop installation's account on the same machine.
  //
  // `--personas-profile=<name>` picks a separate folder, i.e. a separate member: a
  // tester can run several members on one Mac, each launched with its own name
  //   open -n -a "Signal Personas" --args --personas-profile=second
  // Electron's one-instance lock is per data folder, so the copies run side by side.
  const profileArg = process.argv.find(arg => arg.startsWith('--personas-profile='));
  const profile = profileArg
    ?.slice('--personas-profile='.length)
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '')
    .slice(0, 24);
  userData = join(
    app.getPath('appData'),
    profile ? `Signal-Personas-${profile}` : 'Signal-Personas'
  );
} else if (OS.isAppImage()) {
  userData = join(app.getPath('appData'), `${app.getName()} AppImage`);
}

if (userData !== undefined) {
  try {
    mkdirSync(userData, { recursive: true });
  } catch (error) {
    // oxlint-disable-next-line no-console
    console.error('Failed to create userData', Errors.toLogFormat(error));
  }

  app.setPath('userData', userData);
}

// Use console.log because logger isn't fully initialized yet
// oxlint-disable-next-line no-console
console.log(`userData: ${app.getPath('userData')}`);

const userDataPath = app.getPath('userData');
const targetPath = join(userDataPath, 'config.json');

export const userConfig = start({
  name: 'user',
  targetPath,
  throwOnFilesystemErrors: true,
});

export const get = userConfig.get.bind(userConfig);
export const remove = userConfig.remove.bind(userConfig);
export const set = userConfig.set.bind(userConfig);
