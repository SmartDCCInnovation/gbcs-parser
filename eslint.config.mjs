// @ts-check

import eslint from '@eslint/js'
import tseslint from 'typescript-eslint'
import globals from 'globals'
import prettiereslint from 'eslint-plugin-prettier'

export default tseslint.config({
  languageOptions: {
    ecmaVersion: 2021,
    sourceType: 'module',
    globals: { ...globals.nodeBuiltin },
    parserOptions: {
      ecmaVersion: 2021,
      project: './tsconfig.json',
    },
  },
  extends: [
    eslint.configs.recommended,
    ...tseslint.configs.recommended,
    prettiereslint.recommended,
  ],
  rules: {
    eqeqeq: ['error', 'always'],
  },
  ignores: [
    '**/eslint.config.mjs',
    '**/jest.config.js',
    '**/*.test.ts',
    'test/dummy-keystore.ts',
    'dist/**',
  ],
})
