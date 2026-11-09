#!/usr/bin/env node
/**
 * Type-check the real application sources.
 *
 * `npm run typecheck` used to run `vue-tsc --noEmit -p tsconfig.json`, but the
 * root `tsconfig.json` is a Nuxt *solution* config: it carries `"files": []`
 * and only project references. Without `--build`, `tsc` honours the empty file
 * list, checks nothing, and exits 0 — the script reported success while
 * covering zero app files (audit UI-06). `--build` traverses the referenced
 * projects (`app`, `server`, `shared`, `node`) and checks them for real.
 *
 * Turning that on surfaces a pre-existing backlog of type errors that was
 * hidden for as long as the script was broken. Failing the gate outright
 * would make it permanently red and therefore useless, so this wrapper
 * enforces a **ratchet** instead:
 *
 *   - the current error count must not exceed BASELINE_ERRORS;
 *   - any improvement below the baseline is reported, so the number can be
 *     lowered as the backlog is worked off.
 *
 * The ratchet is the honest option: it blocks new type errors immediately
 * without pretending the existing ones are fixed. Lower BASELINE_ERRORS
 * whenever you fix some — the script tells you the new number.
 */

import { spawnSync } from 'node:child_process'

/**
 * Maximum tolerated type errors in app/server/shared sources.
 *
 * 153 at the time UI-06 enabled real checking; 151 after UI-159 part 2 fixed
 * the two `tableColumns` prop errors (UI-10). Every remaining error predates
 * this change. Lower this as the backlog shrinks; never raise it.
 */
const BASELINE_ERRORS = 149

const SOURCE_ERROR_RE = /^(app|server|shared)\/.*error TS\d+/

const result = spawnSync(process.execPath, ['node_modules/vue-tsc/bin/vue-tsc.js', '--build', '--force', 'tsconfig.json'], {
  encoding: 'utf8',
  shell: false,
})

const output = `${result.stdout ?? ''}${result.stderr ?? ''}`
const errorLines = output.split('\n').filter((line) => SOURCE_ERROR_RE.test(line))
const count = errorLines.length

if (count > BASELINE_ERRORS) {
  process.stdout.write(output)
  console.error(
    `\ntypecheck: ${count} type errors in app/server/shared sources exceeds the ` +
      `baseline of ${BASELINE_ERRORS}.\nFix the new errors, or justify and update ` +
      `BASELINE_ERRORS in scripts/typecheck.mjs.`,
  )
  process.exit(1)
}

if (count < BASELINE_ERRORS) {
  console.log(
    `typecheck: ${count} pre-existing type errors (baseline ${BASELINE_ERRORS}).\n` +
      `Improvement detected — lower BASELINE_ERRORS in scripts/typecheck.mjs to ${count} to lock it in.`,
  )
} else {
  console.log(`typecheck: ${count} pre-existing type errors, matching the baseline. No new errors.`)
}

// A non-source failure (config error, crash) must still fail the gate.
if (result.status !== 0 && count === 0) {
  process.stdout.write(output)
  console.error('\ntypecheck: vue-tsc failed without reporting source errors.')
  process.exit(result.status ?? 1)
}
