/** @typedef {import("prettier").Config} PrettierConfig */
/** @typedef {import("@ianvs/prettier-plugin-sort-imports").PluginConfig} SortImportsConfig */

/** @type { PrettierConfig | SortImportsConfig  } */
const config = {
  plugins: ['@ianvs/prettier-plugin-sort-imports'],
  importOrder: [
    '<TYPES>',
    '^(expo(.*)$)|^(expo$)',
    '<THIRD_PARTY_MODULES>',
    '',
    '<TYPES>^@protokoll',
    '^@protokoll/(.*)$',
    '',
    '<TYPES>^[.|..|~]',
    '^~/',
    '^[../]',
    '^[./]',
  ],
  importOrderParserPlugins: ['typescript', 'jsx', 'decorators-legacy'],
  importOrderTypeScriptVersion: '5.4.5',
  // https://github.com/nodejs/nodejs.org/
  singleQuote: true,
  trailingComma: 'es5',
  arrowParens: 'avoid',
};

export default config;
