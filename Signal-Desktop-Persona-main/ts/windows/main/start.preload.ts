// Copyright 2017 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import { contextBridge } from 'electron';

import { createLogger } from '../../logging/log.std.ts';

import '../context.preload.ts';

// Connect websocket early
import '../../textsecure/preconnect.preload.ts';

import './phase0-devtools.node.ts';
import './phase1-ipc.preload.ts';
import '../preload.preload.ts';
import './phase2-dependencies.preload.ts';
import './phase3-post-signal.preload.ts';
import './phase4-test.preload.ts';

import type {
  CdsLookupOptionsType,
  GetIceServersResultType,
} from '../../textsecure/WebAPI.preload.ts';
import {
  cdsLookup,
  deleteFromSVR2,
  getSocketStatus,
  restoreFromSVR2,
  storeWithSVR2,
} from '../../textsecure/WebAPI.preload.ts';
import type { FeatureFlagType } from '../../window.d.ts';
import type { StorageAccessType } from '../../types/Storage.d.ts';
import { calling } from '../../services/calling.preload.ts';
import { Environment, getEnvironment } from '../../environment.std.ts';
import { isProduction } from '../../util/version.std.ts';
import { benchmarkConversationOpen } from '../../CI/benchmarkConversationOpen.preload.ts';
import { itemStorage } from '../../textsecure/Storage.preload.ts';
import { getSelectedConversationId } from '../../state/selectors/nav.std.ts';
import * as Bytes from '../../Bytes.std.ts';
import {
  getPersonasEngine,
  composePersonaPost,
} from '../../services/personasEngine.preload.ts';
import { ensurePersonaJoined } from '../../services/personasMembership.preload.ts';
import {
  sendPersonaBanPoll,
  sendPersonaRate,
  sendPersonaScan,
  sendPersonaVote,
} from '../../services/personasActions.preload.ts';

const log = createLogger('start');

window.addEventListener('contextmenu', e => {
  const node = e.target as Element | null;

  const isEditable = Boolean(
    node?.closest('textarea, input, [contenteditable="plaintext-only"]')
  );
  const isLink = Boolean(node?.closest('a'));
  const isImage = Boolean(node?.closest('.Lightbox img'));
  const hasSelection = Boolean(window.getSelection()?.toString());

  if (!isEditable && !hasSelection && !isLink && !isImage) {
    e.preventDefault();
  }
});

if (window.SignalContext.config.proxyUrl) {
  log.info('Using provided proxy url');
}

if (
  !isProduction(window.SignalContext.getVersion()) ||
  window.SignalContext.config.devTools
) {
  const testKey = 'p10bLPYMs6SjewuhrdWUK2hoqR0Jc/+56GuA/+VBZRg=';

  const SignalDebug = {
    restoreFromSVR2: async (pin: string, expectedKey = testKey) => {
      const result = await restoreFromSVR2({ pin });

      if (result.success) {
        const inBase64 = Bytes.toBase64(result.data);
        const match = inBase64 === expectedKey;
        return { ...result, match };
      }

      return result;
    },
    deleteFromSVR2: async () => {
      return deleteFromSVR2();
    },
    storeWithSVR2: async (pin: string, key = testKey) => {
      return storeWithSVR2({
        pin,
        data: Bytes.fromBase64(key),
      });
    },
    cdsLookup: (options: CdsLookupOptionsType) => cdsLookup(options),
    getSelectedConversation: () => {
      const conversationId = getSelectedConversationId(
        window.reduxStore.getState()
      );
      return window.ConversationController.get(conversationId)?.attributes;
    },
    archiveSessionsForCurrentConversation: async () => {
      const conversationId = getSelectedConversationId(
        window.reduxStore.getState()
      );
      await window.ConversationController.archiveSessionsForConversation(
        conversationId
      );
    },
    getConversations: () =>
      window.ConversationController.getAll().map(
        conversation => conversation.attributes
      ),
    getConversation: (id: string) => window.ConversationController.get(id),
    getMessageById: (id: string) => window.MessageCache.getById(id)?.attributes,
    getMessageBySentAt: async (timestamp: number) => {
      const message = await window.MessageCache.findBySentAt(
        timestamp,
        () => true
      );
      return message?.attributes;
    },
    getReduxState: () => window.reduxStore.getState(),
    getSfuUrl: () => calling.sfuUrl,
    getIceServerOverride: () => calling._iceServerOverride,
    getSocketStatus: () => getSocketStatus(),
    getStorageItem: (name: keyof StorageAccessType) => itemStorage.get(name),
    putStorageItem: <K extends keyof StorageAccessType>(
      name: K,
      value: StorageAccessType[K]
    ) => itemStorage.put(name, value),
    setFlag: (name: keyof FeatureFlagType, value: boolean) => {
      if (!Object.hasOwn(window.Flags, name)) {
        return;
      }
      window.Flags[name] = value;
    },
    setSfuUrl: async (url: string) => {
      await itemStorage.put('sfuUrl', url);
    },
    setIceServerOverride: (
      override: GetIceServersResultType | string | undefined
    ) => {
      if (typeof override === 'string') {
        if (!/(turn|turns|stun):.*/.test(override)) {
          log.warn(
            'Override url should be prefixed with `turn:`, `turns:`, or `stun:` else override may not work'
          );
        }
      }

      calling._iceServerOverride = override;
    },
    // Personas demo: console access to the ZK content path. As of Phase 6 none of
    // this is REQUIRED any more — join happens automatically on the first persona
    // action, rating is a 👍/👎, polls come from the composer's poll modal, voting is
    // the poll bubble, and scans run on a timer. These stay as inspection tools and
    // for scripted benchmark runs.
    personasJoin: async () => {
      const conversation = window.ConversationController.get(
        getSelectedConversationId(window.reduxStore.getState())
      );
      if (!conversation) {
        return 'no conversation selected';
      }
      // Route through the same membership service the UI uses, so the two cannot
      // disagree about whether this instance has joined (a second join for one
      // account is exactly what the anti-Sybil accounting must not see).
      const joined = await ensurePersonaJoined(conversation);
      return joined ? 'joined' : 'join failed (see log)';
    },
    personasPost: async (
      text: string,
      options?: { anon?: boolean; index?: number; context?: number }
    ) => {
      const conversation = window.ConversationController.get(
        getSelectedConversationId(window.reduxStore.getState())
      );
      if (!conversation) {
        return 'no conversation selected';
      }
      // Mirrors the composer: an unlimited plain pseudonym takes a fresh nonce and
      // no topic; a rate-limited one needs the topic's context.
      let choice;
      if (options?.anon) {
        choice = { kind: 'anon' as const };
      } else if (options?.index != null) {
        if (options.context == null) {
          return 'a rate-limited persona needs a topic context: personasPost(text, { index, context })';
        }
        choice = {
          kind: 'rate' as const,
          index: options.index,
          context: options.context,
        };
      } else {
        choice = {
          kind: 'pseudo' as const,
          nonce:
            options?.context ?? Math.floor(Math.random() * 2 ** 48) + 1,
        };
      }
      // Join first, exactly as the composer does — posting un-joined throws inside
      // the engine and used to degrade into a plain, attributable message.
      if (!(await ensurePersonaJoined(conversation))) {
        return 'join failed; refusing to post attributably';
      }
      const post = composePersonaPost(text, choice);
      if (!post) {
        return 'personas engine disabled or unavailable';
      }
      // Display is the plaintext + persona; the wire carries the record (swapped
      // in by the send path via personaRecordBase64).
      await conversation.enqueueMessageForSend({
        body: post.body,
        attachments: [],
        persona: post.persona,
        personaFlagged: false,
        personaEh: post.eh,
        personaRecordBase64: post.personaRecordBase64,
      });
      return `posted as ${post.persona ? `~${post.persona}` : '(anonymous)'} (eh ${post.eh.slice(0, 12)}…)`;
    },
    // Phase 6 console equivalents of the native gestures, for scripted runs.
    personasRate: async (targetEh: string, delta = 1) => {
      const conversation = window.ConversationController.get(
        getSelectedConversationId(window.reduxStore.getState())
      );
      if (!conversation) {
        return 'no conversation selected';
      }
      return (await sendPersonaRate(conversation, targetEh, delta))
        ? `rated ${targetEh.slice(0, 12)}… by ${delta}`
        : 'rate failed (see log)';
    },
    personasBanPoll: async (targetEh: string, persona?: string) => {
      const conversation = window.ConversationController.get(
        getSelectedConversationId(window.reduxStore.getState())
      );
      if (!conversation) {
        return 'no conversation selected';
      }
      return (await sendPersonaBanPoll(conversation, targetEh, persona))
        ? `ban poll opened on ${targetEh.slice(0, 12)}…`
        : 'ban poll failed (see log)';
    },
    personasVote: async (pollEh: string, optionIndex: number) => {
      const conversation = window.ConversationController.get(
        getSelectedConversationId(window.reduxStore.getState())
      );
      if (!conversation) {
        return 'no conversation selected';
      }
      return (await sendPersonaVote(conversation, pollEh, optionIndex))
        ? `voted option ${optionIndex}`
        : 'vote failed (see log)';
    },
    personasScan: async () => {
      const conversation = window.ConversationController.get(
        getSelectedConversationId(window.reduxStore.getState())
      );
      if (!conversation) {
        return 'no conversation selected';
      }
      return (await sendPersonaScan(conversation))
        ? 'scan sent'
        : 'scan failed (see log)';
    },
    personasRender: () => getPersonasEngine()?.render() ?? 'engine unavailable',
    personasPolls: () =>
      getPersonasEngine()?.renderPolls() ?? 'engine unavailable',
    personasLog: () => getPersonasEngine()?.log() ?? 'engine unavailable',
    personasBarrier: () =>
      getPersonasEngine()?.currentBarrier() ?? 'engine unavailable',
    personasFingerprint: () =>
      getPersonasEngine()?.fingerprint() ?? 'engine unavailable',
    ...(window.SignalContext.config.ciMode === 'benchmark'
      ? {
          benchmarkConversationOpen,
        }
      : {}),
  };

  if (getEnvironment() !== Environment.Test) {
    contextBridge.exposeInMainWorld('SignalDebug', SignalDebug);
  }
}

// See ts/logging/log.ts
if (
  getEnvironment() !== Environment.PackagedApp &&
  getEnvironment() !== Environment.Test
) {
  const debug = (...args: Array<string>) => {
    localStorage.setItem('debug', args.join(','));
  };
  contextBridge.exposeInMainWorld('debug', debug);
}

if (window.SignalContext.config.ciMode === 'full') {
  contextBridge.exposeInMainWorld('SignalCI', window.SignalCI);
}

if (getEnvironment() !== Environment.Test) {
  contextBridge.exposeInMainWorld('showDebugLog', window.IPC.showDebugLog);
  contextBridge.exposeInMainWorld('startApp', window.startApp);
}
