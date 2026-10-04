// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo: non-interactive standalone registration against the self-hosted
// Signal-Server *test-server*. This replaces the human "Set Up as Standalone Device"
// flow so a demo/benchmark instance registers itself at boot with no UI ("no
// registration stuff"). It only makes sense against the test server, where the
// captcha token and verification code are stubbed (see deploy/signal-test-server/
// verify.sh and docs/RUNNING_E2_LOCALLY.md). Gated on the PERSONAS_AUTO_REGISTER
// env var so it is inert in any normal build.

import { createLogger } from '../logging/log.std.ts';
import { accountManager } from './AccountManager.preload.ts';
import {
  createVerificationSession,
  requestCodeForVerificationSession,
  submitCaptchaForVerificationSession,
  submitCodeForVerificationSession,
} from './WebAPI.preload.ts';
import { VerificationTransport } from '../types/VerificationTransport.std.ts';
import { PhoneNumberDiscoverability } from '../util/phoneNumberDiscoverability.std.ts';
import { DataWriter } from '../sql/Client.preload.ts';
import { getConversation } from '../util/getConversation.preload.ts';
import { writeProfile } from '../services/writeProfile.preload.ts';
import { toLogFormat } from '../types/errors.std.ts';

const log = createLogger('personaAutoRegister');

// The test-server accepts this fixed captcha token and any verification code.
// Confirmed via deploy/signal-test-server/verify.sh:
//   session -> PATCH {captcha: TEST_SERVER_CAPTCHA} -> allowedToRequestCode: true
//   PUT {code: <anything>} -> verified: true
const TEST_SERVER_CAPTCHA = 'noop.noop.registration.noop';
const TEST_SERVER_CODE = '999999';

// The E.164 to register as, e.g. "+12025550001". Set per instance alongside
// NODE_APP_INSTANCE so each demo member gets its own account/storage profile.
export function getAutoRegisterNumber(): string | undefined {
  const number = process.env.PERSONAS_AUTO_REGISTER?.trim();
  return number ? number : undefined;
}

// Drives the standalone-registration network sequence with the test server's stub
// captcha + code, then creates the primary-device account. registerAsPrimaryDevice
// generates the ACI/PNI identity keys internally and manages the registration baton;
// on success it fires `registration_done`, which the normal boot flow handles
// (Registration.markDone + our-conversation setup). No PIN (SVR2 is DISCARDed in
// libsignal-net localTestServer mode) and no profile is set here.
//
// NOTE (Phase 5): registerAsPrimaryDevice is the injection point for the shared
// phantom ACI identity keypair — AccountManager.preload.ts generates aciKeyPair at
// its line ~430 today; that is where the group-derived keypair will be supplied.
export async function personaAutoRegister(number: string): Promise<void> {
  log.info(`starting non-interactive registration for ${number}`);

  const { sessionId } = await createVerificationSession(number);
  log.info('created verification session');

  await submitCaptchaForVerificationSession({
    phoneNumber: number,
    verificationSessionId: sessionId,
    captchaToken: TEST_SERVER_CAPTCHA,
  });
  log.info('captcha accepted; allowed to request code');

  // The test server stubs SMS delivery; Desktop's normal flow still requests a code
  // before verifying, so we mirror it. If this ever fails against the test server,
  // it can be dropped (verify.sh verifies without a prior request).
  await requestCodeForVerificationSession({
    phoneNumber: number,
    verificationSessionId: sessionId,
    transport: VerificationTransport.SMS,
    languages: ['en'],
  });

  await submitCodeForVerificationSession({
    phoneNumber: number,
    verificationSessionId: sessionId,
    code: TEST_SERVER_CODE,
  });
  log.info('session verified');

  await accountManager.registerAsPrimaryDevice({
    number,
    sessionId,
    phoneNumberDiscoverability: PhoneNumberDiscoverability.NotDiscoverable,
  });
  log.info('account created — registration complete');
}

let profileUploaded = false;

// GroupV2 membership requires each member's profileKeyCredential, which the server
// only issues once that member has uploaded a versioned profile carrying its
// profile-key commitment. The auto-register path skips the human profile stage, so
// nothing is uploaded and peers fetching our credential get none ("Included
// credential request, but got no credential") — group creation then fails with
// "member was missing profileKeyCredential". Upload a minimal versioned profile
// (just a display name) after registration to close that gap. Gated + idempotent
// per process; call once our own conversation exists (post-registration boot).
export async function ensureDemoProfileUploaded(): Promise<void> {
  if (!getAutoRegisterNumber() || profileUploaded) {
    return;
  }
  const us = window.ConversationController.getOurConversationOrThrow();
  const firstName =
    process.env.NODE_APP_INSTANCE?.trim() || us.get('e164') || 'Personas';
  us.set({ profileName: firstName });
  await DataWriter.updateConversation(us.attributes);
  try {
    await writeProfile(getConversation(us), {
      keepAvatar: false,
      avatarUpdate: { oldAvatar: undefined, newAvatar: undefined },
    });
    profileUploaded = true;
    log.info(`uploaded demo versioned profile as "${firstName}"`);
  } catch (error) {
    log.error(`failed to upload demo profile: ${toLogFormat(error)}`);
  }
}
