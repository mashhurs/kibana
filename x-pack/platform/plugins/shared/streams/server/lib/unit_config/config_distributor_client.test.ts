/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createHash } from 'crypto';
import YAML from 'yaml';
import { loggerMock } from '@kbn/logging-mocks';
import type { StreamsUnit } from '@kbn/streams-schema';
import { createConfigDistributorClient } from './config_distributor_client';
import type { UnitCredential } from './types';

const unit: StreamsUnit.Configuration = {
  sources: [
    {
      id: 'otlp-input',
      type: 'nop',
      supported_telemetry: ['logs'],
    },
  ],
  destinations: [
    {
      id: 'es-prod',
      type: 'debug',
      supported_telemetry: ['logs'],
    },
  ],
  pipelines: [
    {
      id: 'main',
      supported_telemetry: ['logs'],
      config: [
        { name: 'sources', value: ['otlp-input'] },
        { name: 'destinations', value: ['es-prod'] },
      ],
    },
  ],
};

const expectedYaml = YAML.stringify(unit);
const KID = '20260921_101500_a3f19b2c';

const hashPublishPayload = (unitYaml: string, credentialFingerprint?: string): string => {
  const hash = createHash('sha256').update(unitYaml, 'utf8');
  if (credentialFingerprint) {
    hash.update('\n');
    hash.update(credentialFingerprint);
  }
  return hash.digest('hex');
};

describe('createConfigDistributorClient', () => {
  it('logs an error and does not call the distributor when the URL is not configured', async () => {
    const fetchImpl = jest.fn();
    const logger = loggerMock.create();
    const { publish, validate } = createConfigDistributorClient({
      config: { ssl: {} },
      logger,
      fetchImpl,
    });

    await expect(publish({ unitId: 'default', unit, secrets: {} })).rejects.toMatchObject({
      statusCode: 503,
    });
    await expect(validate(unit)).rejects.toMatchObject({
      statusCode: 503,
    });

    expect(fetchImpl).not.toHaveBeenCalled();
    expect(logger.error).toHaveBeenCalledTimes(2);
  });

  it('PUTs authored unit YAML and a SHA-256 config hash without mutating the unit', async () => {
    const fetchImpl = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => '',
    });
    const { publish } = createConfigDistributorClient({
      config: { url: 'https://distributor.example:8443/', ssl: {} },
      logger: loggerMock.create(),
      fetchImpl,
    });

    await publish({ unitId: 'default', unit, secrets: {} });

    expect(fetchImpl).toHaveBeenCalledWith(
      'https://distributor.example:8443/v1/units/default',
      expect.objectContaining({
        method: 'PUT',
        body: JSON.stringify({
          unit_yaml: expectedYaml,
          config_hash: hashPublishPayload(expectedYaml),
        }),
      })
    );
  });

  it('sends credentials as a sidecar after sealing secrets under the wrap key', async () => {
    const fetchImpl = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => '',
    });
    const secrets = { es_api_key: 's3cret', s3_secret: 'bucket' };
    const credentials: UnitCredential[] = [
      { name: 'es_api_key', kid: KID, iv: 'iv-es', ciphertext: 'cipher-es' },
      { name: 's3_secret', kid: KID, iv: 'iv-s3', ciphertext: 'cipher-s3' },
    ];
    const encryptCredentials = jest
      .fn()
      .mockResolvedValue({ credentials, fingerprint: 'finger-print' });
    const { publish } = createConfigDistributorClient({
      config: { url: 'https://distributor.example:8443', ssl: {} },
      logger: loggerMock.create(),
      hooks: { encryptCredentials },
      fetchImpl,
    });

    await publish({ unitId: 'default', unit, secrets });

    expect(encryptCredentials).toHaveBeenCalledWith(secrets);
    const body = JSON.parse(fetchImpl.mock.calls[0][1].body);
    expect(body.unit_yaml).toEqual(expectedYaml);
    expect(body.credentials).toEqual(credentials);
    expect(body.config_hash).toEqual(hashPublishPayload(expectedYaml, 'finger-print'));
  });

  it('hashes off the fingerprint, so re-sealing an unchanged secret stays unchanged', async () => {
    const fetchImpl = jest.fn().mockResolvedValue({ ok: true, status: 200, text: async () => '' });
    const secrets = { es_api_key: 's3cret' };
    // AES-GCM is randomized: the same secret seals to different bytes each
    // time. The config_hash must not move with it, or every publish rolls the
    // collector Deployment.
    const encryptCredentials = jest
      .fn()
      .mockResolvedValueOnce({
        credentials: [{ name: 'es_api_key', kid: KID, iv: 'iv-1', ciphertext: 'cipher-1' }],
        fingerprint: 'finger-print',
      })
      .mockResolvedValueOnce({
        credentials: [{ name: 'es_api_key', kid: KID, iv: 'iv-2', ciphertext: 'cipher-2' }],
        fingerprint: 'finger-print',
      });
    const { publish } = createConfigDistributorClient({
      config: { url: 'https://distributor.example:8443', ssl: {} },
      logger: loggerMock.create(),
      hooks: { encryptCredentials },
      fetchImpl,
    });

    await publish({ unitId: 'default', unit, secrets });
    await publish({ unitId: 'default', unit, secrets });

    const [first, second] = fetchImpl.mock.calls.map(([, init]) => JSON.parse(init.body));
    expect(second.config_hash).toEqual(first.config_hash);
    expect(second.credentials).not.toEqual(first.credentials);
  });

  it('publishes without a credentials sidecar when project-key encryption is not configured', async () => {
    const fetchImpl = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => '',
    });
    const logger = loggerMock.create();
    const { publish } = createConfigDistributorClient({
      config: { url: 'https://distributor.example:8443', ssl: {} },
      logger,
      fetchImpl,
    });

    await publish({ unitId: 'default', unit, secrets: { es_api_key: 's3cret' } });

    expect(logger.warn).toHaveBeenCalled();
    const body = JSON.parse(fetchImpl.mock.calls[0][1].body);
    expect(body.credentials).toBeUndefined();
    expect(body.unit_yaml).toEqual(expectedYaml);
    expect(body.unit_yaml).not.toContain('s3cret');
  });

  it('POSTs unit YAML to /v1/validate without credentials', async () => {
    const fetchImpl = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ valid: true, diagnostics: [] }),
    });
    const { validate } = createConfigDistributorClient({
      config: { url: 'https://distributor.example:8443/', ssl: {} },
      logger: loggerMock.create(),
      fetchImpl,
    });

    await expect(validate(unit)).resolves.toEqual({});

    expect(fetchImpl).toHaveBeenCalledWith(
      'https://distributor.example:8443/v1/validate',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ unit_yaml: expectedYaml }),
      })
    );
  });

  it('accepts a valid unit that includes warning diagnostics', async () => {
    const fetchImpl = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () =>
        JSON.stringify({
          valid: true,
          diagnostics: [{ severity: 'warning', code: 'unused_field', message: 'field is unused' }],
          compiled_config: 'receivers: {}',
        }),
    });
    const { validate } = createConfigDistributorClient({
      config: { url: 'https://distributor.example:8443', ssl: {} },
      logger: loggerMock.create(),
      fetchImpl,
    });

    await expect(validate(unit)).resolves.toEqual({ compiled_config: 'receivers: {}' });
  });

  it('rejects an invalid unit with distributor diagnostics', async () => {
    const diagnostics = [
      {
        severity: 'error',
        code: 'invalid_ottl',
        message: 'OTTL parse error',
        path: 'processors > add-env',
        line: 4,
      },
    ];
    const fetchImpl = jest.fn().mockResolvedValue({
      ok: false,
      status: 400,
      text: async () => JSON.stringify({ valid: false, diagnostics }),
    });
    const { validate } = createConfigDistributorClient({
      config: { url: 'https://distributor.example:8443', ssl: {} },
      logger: loggerMock.create(),
      fetchImpl,
    });

    await expect(validate(unit)).rejects.toMatchObject({
      message: 'OTTL parse error',
      statusCode: 400,
      data: { valid: false, diagnostics },
    });
  });
});
