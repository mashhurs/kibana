/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createDecipheriv } from 'crypto';
import { loggerMock } from '@kbn/logging-mocks';
import { createCredentialSealer } from './seal_credentials';
import type { UnitCredential } from './types';
import type { WrapKeyStore } from './wrap_key_store';

const KID = '20260921_101500_a3f19b2c';
const TARGET_ID = 'project-abc';
const AUTH_TAG_BYTES = 16;

/**
 * The unwrap the unit collector performs (ingest-dev#9550), written out here so
 * a change to the blob layout, the AAD, or the tag position fails on this side
 * too rather than only in the collector.
 */
const unwrap = ({
  credential,
  key,
  targetId = TARGET_ID,
}: {
  credential: UnitCredential;
  key: Buffer;
  targetId?: string;
}): string => {
  const sealed = Buffer.from(credential.ciphertext, 'base64');
  const ciphertext = sealed.subarray(0, sealed.length - AUTH_TAG_BYTES);
  const authTag = sealed.subarray(sealed.length - AUTH_TAG_BYTES);

  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(credential.iv, 'base64'));
  decipher.setAAD(Buffer.from(targetId, 'utf8'));
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
};

describe('createCredentialSealer', () => {
  // A fresh buffer per read, since the sealer zeroes what it is handed.
  const storeFor = (kid = KID, fill = 7): WrapKeyStore => ({
    readCurrent: jest.fn(async () => ({ kid, key: Buffer.alloc(32, fill) })),
  });

  const sealerFor = (store: WrapKeyStore, targetId = TARGET_ID) =>
    createCredentialSealer({ store, targetId, logger: loggerMock.create() });

  it('seals each secret under the current kid so the collector can unwrap it', async () => {
    const secrets = { es_api_key: 's3cret', s3_secret: 'bucket-key' };

    const { credentials } = await sealerFor(storeFor())(secrets);

    expect(credentials.map(({ name }) => name)).toEqual(['es_api_key', 's3_secret']);
    for (const credential of credentials) {
      expect(credential.kid).toBe(KID);
      expect(unwrap({ credential, key: Buffer.alloc(32, 7) })).toBe(secrets[credential.name]);
    }
  });

  it('never puts plaintext in the blob', async () => {
    const { credentials } = await sealerFor(storeFor())({ es_api_key: 's3cret' });

    expect(JSON.stringify(credentials)).not.toContain('s3cret');
  });

  it('uses a fresh 96-bit IV for every credential and every seal', async () => {
    const secrets = { a: 'one', b: 'two' };
    const sealer = sealerFor(storeFor());

    const first = await sealer(secrets);
    const second = await sealer(secrets);
    const ivs = [...first.credentials, ...second.credentials].map(({ iv }) => iv);

    expect(new Set(ivs).size).toBe(4);
    for (const iv of ivs) {
      expect(Buffer.from(iv, 'base64')).toHaveLength(12);
    }
  });

  it('re-reads the slot pointer on every seal, so a rotation is picked up', async () => {
    const store = storeFor();

    await sealerFor(store)({ es_api_key: 's3cret' });
    await sealerFor(store)({ es_api_key: 's3cret' });

    expect(store.readCurrent).toHaveBeenCalledTimes(2);
  });

  it('binds the blob to the project, so it cannot be replayed onto another', async () => {
    const { credentials } = await sealerFor(storeFor())({ es_api_key: 's3cret' });

    expect(() =>
      unwrap({ credential: credentials[0], key: Buffer.alloc(32, 7), targetId: 'project-xyz' })
    ).toThrow();
  });

  it('detects a tampered ciphertext', async () => {
    const { credentials } = await sealerFor(storeFor())({ es_api_key: 's3cret' });
    const sealed = Buffer.from(credentials[0].ciphertext, 'base64');
    sealed[0] ^= 0xff;

    expect(() =>
      unwrap({
        credential: { ...credentials[0], ciphertext: sealed.toString('base64') },
        key: Buffer.alloc(32, 7),
      })
    ).toThrow();
  });

  it('fingerprints unchanged secrets identically, so a republish stays a no-op', async () => {
    const secrets = { es_api_key: 's3cret' };
    const sealer = sealerFor(storeFor());

    const first = await sealer(secrets);
    const second = await sealer(secrets);

    expect(second.fingerprint).toBe(first.fingerprint);
    // The point of the fingerprint: the ciphertext did change.
    expect(second.credentials[0].ciphertext).not.toBe(first.credentials[0].ciphertext);
  });

  it('changes the fingerprint when a secret value changes', async () => {
    const sealer = sealerFor(storeFor());

    const before = await sealer({ es_api_key: 's3cret' });
    const after = await sealer({ es_api_key: 'rotated' });

    expect(after.fingerprint).not.toBe(before.fingerprint);
  });

  it('changes the fingerprint when a secret is renamed', async () => {
    const sealer = sealerFor(storeFor());

    const before = await sealer({ es_api_key: 's3cret' });
    const after = await sealer({ s3_secret: 's3cret' });

    expect(after.fingerprint).not.toBe(before.fingerprint);
  });

  it('does not expose the plaintext to an offline guess of the fingerprint', async () => {
    // Same secrets, different wrap key: an unkeyed digest would match.
    const first = await sealerFor(storeFor(KID, 7))({ es_api_key: 's3cret' });
    const second = await sealerFor(storeFor(KID, 9))({ es_api_key: 's3cret' });

    expect(second.fingerprint).not.toBe(first.fingerprint);
  });

  it('propagates a wrap-key read failure instead of sealing', async () => {
    const store: WrapKeyStore = {
      readCurrent: jest.fn(async () => {
        throw new Error('mount is gone');
      }),
    };

    await expect(sealerFor(store)({ es_api_key: 's3cret' })).rejects.toThrow(
      'mount is gone'
    );
  });
});
