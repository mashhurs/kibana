/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { readFile } from 'fs/promises';
import { join } from 'path';
import { StatusError } from '../streams/errors/status_error';

/**
 * Reader for the per-project wrap key that project-controller publishes as
 * Secret `wrap-<project_id>` and Kibana mounts read-only.
 *
 * The mount holds one slot pointer per role and one file per key, so promoting
 * `next` to `current` is a pointer rewrite rather than a key move:
 *
 *   current                            -> "20260921_101500_a3f19b2c"
 *   next                               -> "20260928_101500_7c40de11"
 *   wrap-key.20260921_101500_a3f19b2c  -> 32 raw bytes
 *   wrap-key.20260928_101500_7c40de11  -> 32 raw bytes
 *
 * `previous` may also be present; Kibana never seals with it. Only the unit
 * collector reads it, to unwrap blobs Kibana has not re-sealed yet.
 *
 * Every read goes to disk. The kubelet updates a mounted Secret in place on
 * rotation, so a cached key would keep sealing under a `kid` that is on its way
 * out of the mount, and those blobs would stop unwrapping when the slot is
 * dropped. Reads are two small local files on a tmpfs mount.
 */
export interface WrapKeyMaterial {
  kid: string;
  /** Raw 32-byte AES-256 key. Callers should zero this when done. */
  key: Buffer;
}

export interface WrapKeyStore {
  readCurrent: () => Promise<WrapKeyMaterial>;
}

const AES_256_KEY_BYTES = 32;

/**
 * `<YYYYMMDD>_<HHMMSS>_<8 hex>`, per the `kid` grammar in the project-api
 * `UnitCollectorWrappingKey` schema. Validated because the value is read from
 * the mount and then interpolated into a file name.
 */
const KID_PATTERN = /^[0-9]{8}_[0-9]{6}_[a-f0-9]{8}$/;

const CURRENT_SLOT_FILE = 'current';
const KEY_FILE_PREFIX = 'wrap-key.';

/**
 * 503 rather than 500: a missing or half-written mount is what Kibana sees
 * while project-controller is publishing or rotating, and the caller should
 * retry rather than treat the unit as invalid.
 */
const wrapKeyUnavailable = (message: string): StatusError =>
  new StatusError(`Cannot seal Streams unit credentials: ${message}`, 503);

export const createWrapKeyStore = ({ path }: { path: string }): WrapKeyStore => {
  const readCurrentKid = async (): Promise<string> => {
    const slotFile = join(path, CURRENT_SLOT_FILE);
    let contents: string;

    try {
      contents = await readFile(slotFile, 'utf8');
    } catch (error) {
      throw wrapKeyUnavailable(
        `cannot read the current wrap-key slot at ${slotFile}: ${
          error instanceof Error ? error.message : String(error)
        }. Is Secret wrap-<project_id> mounted at xpack.streams.wrapKey.path?`
      );
    }

    const kid = contents.trim();

    if (!KID_PATTERN.test(kid)) {
      // Deliberately does not echo the contents: on a malformed mount that
      // file could hold anything, including key material.
      throw wrapKeyUnavailable(`${slotFile} does not hold a well-formed kid`);
    }

    return kid;
  };

  const readKey = async (kid: string): Promise<Buffer> => {
    const keyFile = join(path, `${KEY_FILE_PREFIX}${kid}`);
    let key: Buffer;

    try {
      key = await readFile(keyFile);
    } catch (error) {
      // The pointer named a slot whose material is absent. Fail closed; sealing
      // under any other slot would produce a blob the collector rejects.
      throw wrapKeyUnavailable(
        `wrap key ${kid} is named by ${CURRENT_SLOT_FILE} but its material is missing: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }

    if (key.length !== AES_256_KEY_BYTES) {
      key.fill(0);
      throw wrapKeyUnavailable(
        `wrap key ${kid} is ${key.length} bytes, expected ${AES_256_KEY_BYTES} for AES-256`
      );
    }

    return key;
  };

  return {
    readCurrent: async () => {
      const kid = await readCurrentKid();
      return { kid, key: await readKey(kid) };
    },
  };
};
