/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { mkdtemp, rm, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { createWrapKeyStore } from './wrap_key_store';

const KID = '20260921_101500_a3f19b2c';

describe('createWrapKeyStore', () => {
  let mount: string;

  beforeEach(async () => {
    mount = await mkdtemp(join(tmpdir(), 'streams-wrap-key-'));
  });

  afterEach(async () => {
    await rm(mount, { recursive: true, force: true });
  });

  const writeSlot = async (kid: string) => writeFile(join(mount, 'current'), kid);
  const writeKey = async (kid: string, key: Buffer) =>
    writeFile(join(mount, `wrap-key.${kid}`), key);

  it('reads the kid named by `current` and its key material', async () => {
    const key = Buffer.alloc(32, 7);
    await writeSlot(KID);
    await writeKey(KID, key);

    await expect(createWrapKeyStore({ path: mount }).readCurrent()).resolves.toEqual({
      kid: KID,
      key,
    });
  });

  it('tolerates a trailing newline on the slot pointer', async () => {
    await writeSlot(`${KID}\n`);
    await writeKey(KID, Buffer.alloc(32, 7));

    await expect(createWrapKeyStore({ path: mount }).readCurrent()).resolves.toMatchObject({
      kid: KID,
    });
  });

  it('picks up a rotation without restarting, because it does not cache', async () => {
    const rotatedKid = '20260928_101500_7c40de11';
    await writeSlot(KID);
    await writeKey(KID, Buffer.alloc(32, 7));
    const store = createWrapKeyStore({ path: mount });

    await expect(store.readCurrent()).resolves.toMatchObject({ kid: KID });

    await writeKey(rotatedKid, Buffer.alloc(32, 9));
    await writeSlot(rotatedKid);

    await expect(store.readCurrent()).resolves.toEqual({
      kid: rotatedKid,
      key: Buffer.alloc(32, 9),
    });
  });

  it('fails closed when the mount is absent', async () => {
    await expect(
      createWrapKeyStore({ path: join(mount, 'nope') }).readCurrent()
    ).rejects.toMatchObject({ statusCode: 503 });
  });

  it('fails closed when `current` names a kid whose material is missing', async () => {
    await writeSlot(KID);

    await expect(createWrapKeyStore({ path: mount }).readCurrent()).rejects.toMatchObject({
      statusCode: 503,
      message: expect.stringContaining('material is missing'),
    });
  });

  it('rejects a malformed kid rather than reading the file it names', async () => {
    await writeSlot('../../etc/passwd');

    await expect(createWrapKeyStore({ path: mount }).readCurrent()).rejects.toMatchObject({
      statusCode: 503,
      message: expect.stringContaining('well-formed kid'),
    });
  });

  it('does not echo the slot contents, which may hold key material', async () => {
    await writeSlot('not-a-kid-but-possibly-a-secret');

    await expect(createWrapKeyStore({ path: mount }).readCurrent()).rejects.not.toMatchObject({
      message: expect.stringContaining('possibly-a-secret'),
    });
  });

  it('rejects key material that is not an AES-256 key', async () => {
    await writeSlot(KID);
    await writeKey(KID, Buffer.alloc(16, 7));

    await expect(createWrapKeyStore({ path: mount }).readCurrent()).rejects.toMatchObject({
      statusCode: 503,
      message: expect.stringContaining('16 bytes, expected 32'),
    });
  });
});
