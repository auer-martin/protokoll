/// <reference types="./types.d.ts" />
import * as path from 'node:path';
import { includeIgnoreFile } from '@eslint/compat';
import eslint from '@eslint/js';
import drizzlePlugin from 'eslint-plugin-drizzle';
import importPlugin from 'eslint-plugin-import';
import turboPlugin from 'eslint-plugin-turbo';
import unicornPlugin from 'eslint-plugin-unicorn';
import tseslint from 'typescript-eslint';

/**
 * All packages that leverage t3-env should use this rule
 */
export const restrictEnvAccess = tseslint.config(
  { ignores: ['**/env.ts'] },
  {
    files: ['**/*.js', '**/*.ts', '**/*.tsx'],
    rules: {
      'no-restricted-properties': [
        'error',
        {
          object: 'process',
          property: 'env',
          message:
            "Use `import { env } from '~/env'` instead to ensure validated types.",
        },
      ],
      'no-restricted-imports': [
        'error',
        {
          name: 'process',
          importNames: ['env'],
          message:
            "Use `import { env } from '~/env'` instead to ensure validated types.",
        },
      ],
    },
  }
);

export default tseslint.config(
  // Ignore files not tracked by VCS and any config files
  includeIgnoreFile(path.join(import.meta.dirname, '../../.gitignore')),
  { ignores: ['**/*.config.*'] },
  {
    files: ['**/*.js', '**/*.ts', '**/*.tsx'],
    plugins: {
      import: importPlugin,
      unicorn: unicornPlugin,
      turbo: turboPlugin,
      drizzle: drizzlePlugin,
    },
    extends: [
      eslint.configs.recommended,
      ...tseslint.configs.recommended,
      ...tseslint.configs.recommendedTypeChecked,
      ...tseslint.configs.stylisticTypeChecked,
    ],
    rules: {
      ...turboPlugin.configs.recommended.rules,
      ...drizzlePlugin.configs.recommended.rules,

      'drizzle/enforce-delete-with-where': [
        'error',
        { drizzleObjectName: 'db' },
      ],
      'drizzle/enforce-update-with-where': [
        'error',
        { drizzleObjectName: 'db' },
      ],

      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          args: 'after-used',
          caughtErrors: 'none',
          ignoreRestSiblings: true,
          vars: 'all',
        },
      ],
      '@typescript-eslint/consistent-type-imports': [
        'warn',
        { prefer: 'type-imports', fixStyle: 'separate-type-imports' },
      ],
      '@typescript-eslint/no-misused-promises': [
        2,
        { checksVoidReturn: { attributes: false } },
      ],
      '@typescript-eslint/no-unnecessary-condition': [
        'error',
        {
          allowConstantLoopConditions: true,
        },
      ],
      '@typescript-eslint/no-non-null-assertion': 'error',
      'import/consistent-type-specifier-style': ['error', 'prefer-top-level'],
      'prefer-const': 'error',
      'unicorn/filename-case': ['error', { case: 'kebabCase' }],
    },
  },
  {
    linterOptions: { reportUnusedDisableDirectives: true },
    languageOptions: { parserOptions: { project: true } },
  }
);
