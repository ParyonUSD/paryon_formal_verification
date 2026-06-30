import globals from 'globals';
import pluginJs from '@eslint/js';
import tseslint from 'typescript-eslint';

// Mirrors the ParyonUSD paryon_library eslint setup (flat config, @eslint/js + typescript-eslint
// recommended), adapted to a Node project. Catches unused imports/locals and enforces max-len.
export default [
  { files: ['**/*.{js,mjs,cjs,ts}'] },
  { languageOptions: { globals: { ...globals.node } } },
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      'max-len': ['error', { code: 120, ignoreStrings: true, ignoreTemplateLiterals: true }],
    },
  },
  {
    // Transaction templates pin many fields per UTXO; the tabular single-line form reads better than
    // wrapping. max-len is for the reusable engine (src/), not these project-specific fixtures.
    // All other rules (incl. no-unused-vars) still apply to tests.
    files: ['tests/**'],
    rules: { 'max-len': 'off' },
  },
  { ignores: ['dist/', 'node_modules/'] },
];
