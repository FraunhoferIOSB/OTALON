// ESLint 9 flat config for otalon-ui
// Replaces legacy .eslintrc.cjs which extended @nuxtjs/eslint-config-typescript + prettier.
// Behaviour preserved: browser+node globals, Vue+TS support via @nuxt/eslint-config,
// Prettier compatibility via eslint-config-prettier, and the same three custom rules.

import { createConfigForNuxt } from '@nuxt/eslint-config/flat'
import prettier from 'eslint-config-prettier'
import globals from 'globals'

// Polyfill: @nuxt/eslint-config's transitive dep eslint-flat-config-utils calls
// Object.groupBy, which is Node 21+. Production runs Node 22 (see Dockerfile),
// but local dev sandboxes may still be on Node 20. No-op on supported versions.
// Runs before the composer below is invoked.
if (typeof Object.groupBy !== 'function') {
  Object.groupBy = (items, fn) => {
    const out = {}
    let i = 0
    for (const item of items) {
      const key = fn(item, i++)
      ;(out[key] ??= []).push(item)
    }
    return out
  }
}

const isProduction = process.env.NODE_ENV === 'production'

export default createConfigForNuxt({
  features: {
    // Keep stylistic off — Prettier owns formatting.
    stylistic: false,
  },
})
  .append({
    name: 'otalon-ui/globals',
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node,
      },
    },
  })
  .append({
    name: 'otalon-ui/rules',
    rules: {
      'vue/multi-word-component-names': 'off',
      'no-console': isProduction ? 'warn' : 'off',
      'no-debugger': isProduction ? 'warn' : 'off',
      // _ prefix is the project convention for intentionally unused
      // identifiers (destructured tuple positions in test-envelope*.mjs,
      // unused destructured-rest fields, throwaway catch bindings).
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
          destructuredArrayIgnorePattern: '^_',
        },
      ],
      // Base no-unused-vars stays off globally because it lacks
      // TypeScript awareness and false-positives on declaration-only
      // identifiers (e.g. the `e` discriminator in defineEmits<{...}>()
      // overloads). The @typescript-eslint variant above replaces it in
      // .ts/.vue files; the .mjs override below re-enables it for plain
      // JS test scripts.
      'no-unused-vars': 'off',
    },
  })
  .append({
    name: 'otalon-ui/mjs-scripts',
    files: ['**/*.mjs'],
    rules: {
      // Plain JS test/debug scripts: enable the base rule (no TypeScript
      // here, so the @typescript-eslint variant is silent). Leading-_
      // pattern matches destructured tuple positions used for clarity.
      'no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
          destructuredArrayIgnorePattern: '^_',
        },
      ],
    },
  })
  // Prettier compatibility — disables ESLint rules that conflict with Prettier.
  // MUST be last so it can turn off rules added by previous configs.
  .append(prettier)
  .append({
    name: 'otalon-ui/ignores',
    ignores: [
      '.nuxt/**',
      '.output/**',
      'dist/**',
      'node_modules/**',
      'shared/**',
      'logs/**',
      'screenshots/**',
      'public/**',
      'tsconfig.tsbuildinfo',
    ],
  })
