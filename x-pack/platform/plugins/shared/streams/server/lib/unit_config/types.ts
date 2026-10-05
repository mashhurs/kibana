/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { StreamsUnit } from '@kbn/streams-schema';

/**
 * One credential as the config-distributor `PUT /v1/units/{id}` sidecar expects:
 * a name referenced from authored unit YAML, plus the sealed blob
 * `{kid, iv, ciphertext}` agreed in elastic/infosec#28583. Plaintext never
 * appears in `unit_yaml`, and neither the distributor nor streams-controller
 * can open the blob — only the unit collector, which mounts the same wrap key.
 */
export interface UnitCredential {
  name: string;
  /**
   * Identifies the wrap-key slot this blob was sealed under, so the collector
   * can unwrap by `kid` across a rotation (`current` or `previous`).
   */
  kid: string;
  /** Base64 96-bit AES-GCM nonce. Fresh per credential per seal. */
  iv: string;
  /**
   * Base64 AES-256-GCM ciphertext with the 16-byte authentication tag
   * appended, which is what Go's `cipher.AEAD.Open` expects on the unwrap side.
   */
  ciphertext: string;
}

/**
 * The outcome of sealing a unit's secrets: one blob per secret, and a
 * fingerprint of the sealed *plaintext*.
 *
 * `config_hash` has to cover the secrets so a secret-only edit still rolls out,
 * but it cannot be computed over the ciphertext: AES-GCM is randomized, so
 * re-sealing an unchanged secret produces different bytes every time and every
 * publish would look like a change, rolling the collector Deployment for
 * nothing. The fingerprint is stable for unchanged plaintext under the same
 * `kid`, which keeps the distributor's `unchanged` hash gate working.
 */
export interface SealedCredentials {
  credentials: UnitCredential[];
  fingerprint: string;
}

export interface PublishUnitConfigParams {
  unitId: string;
  unit: StreamsUnit.Configuration;
  secrets: StreamsUnit.Secrets;
}

export type PublishUnitConfig = (params: PublishUnitConfigParams) => Promise<void>;

export type EncryptUnitCredentials = (
  secrets: StreamsUnit.Secrets
) => Promise<SealedCredentials>;

/**
 * Result of config-distributor `POST /v1/validate` when the unit compiles.
 * `compiled_config` is the raw OpenTelemetry collector YAML when the
 * distributor returns it.
 */
export interface UnitValidationResult {
  compiled_config?: string;
}

/**
 * Backend-owned unit config steps. The config-distributor client supplies
 * `validate` and `publish`.
 */
export interface UnitConfigHooks {
  /**
   * Unit validation via config-distributor `POST /v1/validate`. This is the
   * only unit-document check on the write path. Called before the
   * configuration saved object is written. Throw to reject the PUT.
   * Credentials are not required.
   */
  validate?: (unit: StreamsUnit.Configuration) => Promise<UnitValidationResult>;
  /**
   * Publish the unit to config-distributor `PUT /v1/units/{id}` after the
   * configuration saved object is written.
   */
  publish?: PublishUnitConfig;
  /**
   * Outbound transform: seal each named secret under the project wrap key for
   * the distributor `credentials[]` sidecar. Does not rewrite `unit`. Kibana
   * at-rest protection is Encrypted Saved Objects on `secrets`; this is the
   * separate in-flight protection, since the distributor and
   * streams-controller do not read ESO and must never see plaintext.
   *
   * Unset when `xpack.streams.wrapKey.path` is not configured, in which case
   * publishing a unit that has secrets fails rather than sending plaintext.
   */
  encryptCredentials?: EncryptUnitCredentials;
}
