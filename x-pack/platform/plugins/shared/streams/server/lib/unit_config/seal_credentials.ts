/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createCipheriv, createHmac, getFips, randomBytes } from 'crypto';
import type { Logger } from '@kbn/logging';
import type { StreamsUnit } from '@kbn/streams-schema';
import { StatusError } from '../streams/errors/status_error';
import type { EncryptUnitCredentials, SealedCredentials, UnitCredential } from './types';
import type { WrapKeyStore } from './wrap_key_store';

/**
 * 96-bit nonce, the AES-GCM standard size and the only length Go's
 * `cipher.NewGCM` accepts without `NewGCMWithNonceSize` on the unwrap side.
 */
const IV_BYTES = 12;

const CIPHER = 'aes-256-gcm';

/**
 * Seals a unit's destination credentials for the config-distributor sidecar.
 *
 * Kibana keeps the user's plaintext in Encrypted Saved Objects so the value can
 * be re-saved and re-sealed, but that does not help the unit: the distributor
 * and streams-controller do not read ESO and must never see the credential. So
 * each secret is sealed under the project wrap key into `{kid, iv, ciphertext}`
 * and only the blob travels onward, per elastic/infosec#28583.
 *
 * Crypto comes from Node's `crypto`, which is OpenSSL. Under
 * `xpack.security.fipsMode.enabled` that is the FIPS 140-3 validated provider,
 * which is how this path meets the InfoSec requirement; nothing here rolls its
 * own cipher or nonce.
 *
 * Plaintext is held only for the length of one call: it arrives from the
 * request or ESO, goes straight into the cipher, and is never logged or written
 * alongside the sealed output.
 */
export const createCredentialSealer = ({
  store,
  targetId,
  logger,
}: {
  store: WrapKeyStore;
  /**
   * The project this Kibana seals for, bound into the AEAD's additional
   * authenticated data. A blob lifted from one project fails to open in
   * another even though both may hold the same `kid` on their mount.
   */
  targetId: string;
  logger: Logger;
}): EncryptUnitCredentials => {
  if (!getFips()) {
    // Not fatal: local and self-managed development runs outside FIPS mode.
    // Serverless enables it, which is where the InfoSec requirement applies.
    logger.warn(
      'Sealing Streams unit credentials outside FIPS mode. Node is not running with the OpenSSL FIPS provider, so this does not meet the FIPS 140-3 requirement for production.'
    );
  }

  return async (secrets: StreamsUnit.Secrets): Promise<SealedCredentials> => {
    // One read per publish: the slot pointer is checked immediately before the
    // seals it governs, so a rotation cannot land mid-unit and leave some
    // credentials under a kid that is being dropped.
    const { kid, key } = await store.readCurrent();

    try {
      const names = Object.keys(secrets).sort();
      const credentials = names.map((name) => sealOne({ name, key, kid, targetId, secrets }));

      logger.debug(
        `Sealed ${credentials.length} Streams unit credential(s) under wrap key ${kid}.`
      );

      return { credentials, fingerprint: fingerprintSecrets({ key, kid, names, secrets }) };
    } finally {
      // The mounted key does not need to outlive the seal it was read for.
      key.fill(0);
    }
  };
};

const sealOne = ({
  name,
  key,
  kid,
  targetId,
  secrets,
}: {
  name: string;
  key: Buffer;
  kid: string;
  targetId: string;
  secrets: StreamsUnit.Secrets;
}): UnitCredential => {
  // Fresh per credential, from the CSPRNG. Reusing (key, IV) under AES-GCM
  // leaks the XOR of the two plaintexts and the authentication subkey, so this
  // must never be derived from the credential or the unit.
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(CIPHER, key, iv);

  cipher.setAAD(additionalData(targetId));

  const sealed = Buffer.concat([
    cipher.update(secrets[name], 'utf8'),
    cipher.final(),
    // Appended rather than sent as a fourth field: the blob shape is fixed at
    // `{kid, iv, ciphertext}`, and Go's `cipher.AEAD.Open` expects the tag
    // trailing the ciphertext anyway.
    cipher.getAuthTag(),
  ]);

  try {
    return {
      name,
      kid,
      iv: iv.toString('base64'),
      ciphertext: sealed.toString('base64'),
    };
  } finally {
    sealed.fill(0);
  }
};

/**
 * Binds the blob to the project. The collector passes the same bytes to
 * `Open`, so this value is a contract with the unwrap side (ingest-dev#9550)
 * and cannot be extended on one side alone.
 */
const additionalData = (targetId: string): Buffer => Buffer.from(targetId, 'utf8');

/**
 * Stable digest of the plaintext being sealed, for the distributor's
 * `config_hash`.
 *
 * Keyed by the wrap key rather than a plain SHA-256 of the secret: the hash is
 * written to the StreamUnit resource, and credentials are often low-entropy
 * enough to guess offline from an unkeyed digest. Keying means the digest
 * changes on rotation, which is correct — the ciphertext changed too, so the
 * unit does need a roll.
 */
const fingerprintSecrets = ({
  key,
  kid,
  names,
  secrets,
}: {
  key: Buffer;
  kid: string;
  names: string[];
  secrets: StreamsUnit.Secrets;
}): string => {
  const hmac = createHmac('sha256', key);

  hmac.update(kid);

  for (const name of names) {
    // Length-prefixed so that renaming a credential cannot collide with a
    // different set whose concatenation happens to match.
    hmac.update(`\n${name.length}:${name}=${secrets[name].length}:`);
    hmac.update(secrets[name], 'utf8');
  }

  return hmac.digest('hex');
};

export const credentialSealingUnavailable = (): StatusError =>
  new StatusError(
    'Cannot publish Streams unit credentials: xpack.streams.wrapKey.path is not configured, so there is no project wrap key to seal with.',
    503
  );
