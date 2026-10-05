/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import { EuiText } from '@elastic/eui';
import { FormattedMessage } from '@kbn/i18n-react';
import { LocalElasticsearchFields } from './local_elasticsearch_fields';
import type { DestinationCreationFormErrors, DestinationStorageKind } from './types';

interface DestinationTypeFieldsProps {
  storageKind: DestinationStorageKind;
  index: string;
  indexPatterns: string;
  endpoint: string;
  apiKey: string;
  indexError?: DestinationCreationFormErrors['index'];
  indexPatternsError?: DestinationCreationFormErrors['indexPatterns'];
  disabled: boolean;
  onIndexChange: (index: string) => void;
  onIndexPatternsChange: (indexPatterns: string) => void;
  onEndpointChange: (endpoint: string) => void;
  onApiKeyChange: (apiKey: string) => void;
  onBlur: () => void;
}

/**
 * Renders the form section for the selected destination type.
 * Add a case and a fields component when a new type becomes available.
 */
export const DestinationTypeFields = ({
  storageKind,
  index,
  indexPatterns,
  endpoint,
  apiKey,
  indexError,
  indexPatternsError,
  disabled,
  onIndexChange,
  onIndexPatternsChange,
  onEndpointChange,
  onApiKeyChange,
  onBlur,
}: DestinationTypeFieldsProps) => {
  switch (storageKind) {
    case 'local_elasticsearch':
      return (
        <LocalElasticsearchFields
          index={index}
          indexPatterns={indexPatterns}
          endpoint={endpoint}
          apiKey={apiKey}
          indexError={indexError}
          indexPatternsError={indexPatternsError}
          disabled={disabled}
          onIndexChange={onIndexChange}
          onIndexPatternsChange={onIndexPatternsChange}
          onEndpointChange={onEndpointChange}
          onApiKeyChange={onApiKeyChange}
          onBlur={onBlur}
        />
      );
    case 'external_storage':
      return (
        <EuiText size="s" color="subdued">
          <FormattedMessage
            id="xpack.streams.destinations.externalStorageUnavailableDescription"
            defaultMessage="External storage isn't available yet."
          />
        </EuiText>
      );
  }
};
