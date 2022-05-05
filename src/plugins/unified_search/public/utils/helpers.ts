/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

import { IFieldType } from '@kbn/data-views-plugin/common';
import { i18n } from '@kbn/i18n';
import { isEmpty } from 'lodash';
import { validateParams } from '../filter_bar/filter_editor/lib/filter_editor_utils';

export const getFieldValidityAndErrorMessage = (
  field: IFieldType,
  value?: string | undefined
): { isInvalid: boolean; errorMessage: string[] } => {
  const type = field.type;
  let isInvalid = false;
  let errorMessage = [''];

  switch (type) {
    case 'string':
      isInvalid = !validateParams(value, field);
      break;
    case 'date':
    case 'date_range':
      isInvalid = !isEmpty(value) && !validateParams(value, field);
      errorMessage = [
        i18n.translate('unifiedSearch.filter.filterBar.invalidDateFormatProvidedErrorMessage', {
          defaultMessage: 'Invalid date format provided',
        }),
      ];
      break;
    case 'ip':
    case 'ip_range':
      isInvalid = !isEmpty(value) && !validateParams(value, field);
      break;
    case 'number':
    case 'number_range':
    case 'boolean':
    default:
      break;
  }

  return { isInvalid, errorMessage };
};
