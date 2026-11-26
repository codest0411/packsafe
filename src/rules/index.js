import { RULE_PS001 } from './ps001-home-paths.js';
import { RULE_PS002 } from './ps002-identity.js';
import { RULE_PS003 } from './ps003-secrets.js';
import { RULE_PS004 } from './ps004-sourcemaps.js';
import { RULE_PS005 } from './ps005-risky-files.js';
import { RULE_PS006 } from './ps006-internal-urls.js';
import { RULE_PS007 } from './ps007-size-sanity.js';
import { RULE_PS008 } from './ps008-emails.js';

/** @type {import('./types.js').RuleMeta[]} */
export const ALL_RULES = [
  RULE_PS001,
  RULE_PS002,
  RULE_PS003,
  RULE_PS004,
  RULE_PS005,
  RULE_PS006,
  RULE_PS007,
  RULE_PS008
];
