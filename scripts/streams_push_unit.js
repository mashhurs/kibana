#!/usr/bin/env node

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

/**
 * Deploy or delete one Streams unit through the streams-config-distributor.
 *
 * The distributor takes one unit per request: `PUT /v1/units/<unit-id>` upserts
 * the unit's StreamUnit custom resource, `DELETE /v1/units/<unit-id>` removes it.
 * The body is the authored unit YAML plus a SHA-256 of those YAML bytes, which
 * this script computes. Credentials, when present, must already be ciphertext
 * encrypted under the project public key; the distributor never sees plaintext.
 *
 * PUT is idempotent and hash-gated, so re-running with an unchanged unit
 * answers `unchanged` without writing. That is the drift-recovery call Kibana
 * makes periodically.
 *
 * The target is taken from the mTLS client certificate, never from the request,
 * so the certificate decides which project the unit lands in.
 *
 * Requires mTLS. Against the local kind cluster (see the streams-config-distributor
 * repository's Tiltfile), the client certificate lives in the distributor namespace:
 *
 *   NS=streams-config-distributor; CERTS=$(mktemp -d)
 *   kubectl --context kind-streams -n $NS get secret streams-kibana-client \
 *     -o jsonpath='{.data.tls\.crt}' | base64 -d > $CERTS/kibana.crt
 *   kubectl --context kind-streams -n $NS get secret streams-kibana-client \
 *     -o jsonpath='{.data.tls\.key}' | base64 -d > $CERTS/kibana.key
 *   kubectl --context kind-streams -n $NS get secret streams-kibana-client \
 *     -o jsonpath='{.data.ca\.crt}' | base64 -d > $CERTS/server-ca.crt
 *
 * Tilt already forwards 8443, so no port-forward is needed. On a DevShard, take
 * the same secrets from that project's namespace and forward the service port.
 *
 * Usage:
 *   node scripts/streams_push_unit.js [options]
 *
 * Options:
 *   --url <url>        Config-distributor base URL (env: CONFIG_DISTRIBUTOR_URL, default: https://localhost:8443)
 *   --cert <path>      Client cert (PEM)           (env: CONFIG_DISTRIBUTOR_CERT)
 *   --key <path>       Client key (PEM)            (env: CONFIG_DISTRIBUTOR_KEY)
 *   --ca <path>        Server CA cert (PEM)        (env: CONFIG_DISTRIBUTOR_CA)
 *   --server-name <dns> Name to verify the server certificate against (env: CONFIG_DISTRIBUTOR_SERVER_NAME).
 *                      Needed with --ca behind a port-forward, where the URL host is
 *                      localhost but the certificate only carries in-cluster DNS names,
 *                      e.g. streams-config-distributor-service.
 *   --unit-id <id>     Unit id to deploy or delete (default: example-unit)
 *   --unit-file <path> File holding the authored unit YAML (uses a built-in example if omitted)
 *   --delete           Delete the unit instead of deploying it
 *
 * Examples:
 *   node scripts/streams_push_unit.js \
 *     --cert /tmp/certs/kibana.crt --key /tmp/certs/kibana.key --ca /tmp/certs/server-ca.crt
 *
 *   CONFIG_DISTRIBUTOR_CERT=/tmp/certs/kibana.crt \
 *   CONFIG_DISTRIBUTOR_KEY=/tmp/certs/kibana.key \
 *   CONFIG_DISTRIBUTOR_CA=/tmp/certs/server-ca.crt \
 *   node scripts/streams_push_unit.js --unit-id my-unit --unit-file ./my-unit.yml
 *
 *   node scripts/streams_push_unit.js --unit-id my-unit --delete
 */

require('@kbn/setup-node-env');

const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const { URL } = require('url');
const getopts = require('getopts');

const EXAMPLE_UNIT_YAML = `sources:
  - id: otlp-in
    type: otlp
processors: []
destinations:
  - id: es-logs
    type: elasticsearch
`;

function parseArgs() {
  const opts = getopts(process.argv.slice(2), {
    string: ['url', 'cert', 'key', 'ca', 'server-name', 'unit-id', 'unit-file'],
    boolean: ['delete'],
    alias: { 'server-name': 'serverName', 'unit-id': 'unitId', 'unit-file': 'unitFile' },
  });

  return {
    url: opts.url || process.env.CONFIG_DISTRIBUTOR_URL || 'https://localhost:8443',
    cert: opts.cert || process.env.CONFIG_DISTRIBUTOR_CERT,
    key: opts.key || process.env.CONFIG_DISTRIBUTOR_KEY,
    ca: opts.ca || process.env.CONFIG_DISTRIBUTOR_CA,
    serverName:
      opts.serverName || opts['server-name'] || process.env.CONFIG_DISTRIBUTOR_SERVER_NAME,
    unitId: opts.unitId || opts['unit-id'] || 'example-unit',
    unitFile: opts.unitFile || opts['unit-file'],
    remove: opts.delete,
  };
}

function loadUnitYaml(unitFile) {
  if (!unitFile) {
    console.log('No --unit-file provided, using the built-in example unit.');
    return EXAMPLE_UNIT_YAML;
  }
  return fs.readFileSync(unitFile, 'utf8');
}

function tlsOptionsFrom({ cert, key, ca, serverName }) {
  const options = {};
  if (cert) options.cert = fs.readFileSync(cert);
  if (key) options.key = fs.readFileSync(key);
  if (ca) {
    options.ca = fs.readFileSync(ca);
  } else {
    // No CA provided — skip server cert verification (dev convenience only).
    options.rejectUnauthorized = false;
  }
  if (serverName) {
    // Verify against this name instead of the URL host. Behind a port-forward
    // the host is localhost, which the server certificate does not carry.
    options.servername = serverName;
  }
  return options;
}

function request(baseUrl, { method, path, body, tls }) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(path, baseUrl);
    const headers = {};
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(body);
    }

    const req = https.request(
      {
        hostname: parsed.hostname,
        port: parsed.port || 443,
        path: parsed.pathname,
        method,
        headers,
        ...tls,
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => resolve({ statusCode: res.statusCode, body: data }));
      }
    );

    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

function reportFailure(statusCode, body) {
  // The distributor answers failures as text/plain, so surface the body as-is.
  const hint = {
    400: 'the request body or unit id was rejected',
    401: 'a verified mTLS client certificate is required',
    403: 'the client certificate does not identify exactly one target',
    409: 'a concurrent write changed the resource; retry',
    413: 'the body or compiled artifact is over its size limit',
    503: 'the Kubernetes write failed — is the StreamUnit CRD installed and the target namespace present?',
  }[statusCode];

  console.error(`Error: server returned ${statusCode}${hint ? ` (${hint})` : ''}`);
  if (body) console.error('Response body:', body.trim());
  process.exit(1);
}

async function deleteUnit(args, tls) {
  const path = `/v1/units/${encodeURIComponent(args.unitId)}`;
  console.log(`DELETE ${args.url}${path} ...`);

  const { statusCode, body } = await request(args.url, { method: 'DELETE', path, tls });
  if (statusCode !== 204) {
    reportFailure(statusCode, body);
  }
  // 204 covers both "deleted" and "was already gone", so a retry is safe.
  console.log(`Success (204): unit "${args.unitId}" is gone.`);
}

async function putUnit(args, tls) {
  const unitYaml = loadUnitYaml(args.unitFile);
  const configHash = crypto.createHash('sha256').update(unitYaml, 'utf8').digest('hex');
  const path = `/v1/units/${encodeURIComponent(args.unitId)}`;

  console.log(`PUT ${args.url}${path} (config_hash ${configHash}) ...`);

  const { statusCode, body } = await request(args.url, {
    method: 'PUT',
    path,
    body: JSON.stringify({ unit_yaml: unitYaml, config_hash: configHash }),
    tls,
  });

  if (statusCode !== 200) {
    reportFailure(statusCode, body);
  }

  const result = JSON.parse(body);
  const note =
    result.result === 'unchanged'
      ? ' (hash matched, nothing written)'
      : '';
  console.log(
    `Success (200): unit "${result.unit_id}" in target "${result.target_id}" is ${result.result}${note}.`
  );
}

async function main() {
  const args = parseArgs();

  if (!args.cert || !args.key) {
    console.error(
      'Error: --cert and --key are required (or set CONFIG_DISTRIBUTOR_CERT / CONFIG_DISTRIBUTOR_KEY).'
    );
    process.exit(1);
  }

  const tls = tlsOptionsFrom(args);
  if (args.remove) {
    await deleteUnit(args, tls);
    return;
  }
  await putUnit(args, tls);
}

main().catch((err) => {
  console.error('Unexpected error:', err.message);
  process.exit(1);
});
