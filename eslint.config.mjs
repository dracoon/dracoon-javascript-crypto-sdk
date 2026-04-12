import eslintjs from '@eslint/js';
import eslintConfigPrettier from 'eslint-config-prettier/flat';
import { defineConfig, globalIgnores } from 'eslint/config';
import tseslint from 'typescript-eslint';
import globals from 'globals';

export default defineConfig([
    globalIgnores([
        '**/.husky',
        '**/.idea',
        '**/.vscode',
        '**/coverage',
        '**/dependency-check*',
        '**/dist',
        '**/lib',
        '**/example',
        '**/node_modules',
        '**/scripts',
        '**/test',
        '**/rollup.config.js'
    ]),
    eslintjs.configs.recommended,
    tseslint.configs.recommended,
    eslintConfigPrettier,
    {
        languageOptions: {
            globals: {
                ...globals.browser
            }
        }
    },
    {
        files: ['**/*.ts', '**/*.tsx'],
        rules: {
            '@typescript-eslint/no-inferrable-types': 'off',
            '@typescript-eslint/explicit-function-return-type': 'error',
            '@typescript-eslint/explicit-member-accessibility': 'error'
        }
    }
]);
