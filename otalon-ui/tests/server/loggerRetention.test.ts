/** Tests for UI logger rotated-file retention (SUITE-066). */

import { mkdirSync, mkdtempSync, readdirSync, statSync, writeFileSync, utimesSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { beforeAll, describe, expect, it } from 'vitest'

const DAY_MS = 24 * 60 * 60 * 1000

let deleteStaleRotatedFiles: (filePath: string, retentionDays: number, now?: Date) => string[]

beforeAll(async () => {
  const tmpLogDir = mkdtempSync(join(tmpdir(), 'ui-log-'))
  process.env.LOG_FILE = join(tmpLogDir, 'ui.log')
  process.env.UI_LOG_RETENTION_DAYS = '14'
  const mod = await import('../../server/utils/logger')
  deleteStaleRotatedFiles = mod.deleteStaleRotatedFiles
})

function makeRotatedFiles(logPath: string, names: string[]): void {
  const dir = join(logPath, '..')
  mkdirSync(dir, { recursive: true })
  for (const name of names) {
    writeFileSync(join(dir, name), 'old log content')
  }
}

function ageFile(path: string, days: number, now: Date): void {
  const stamp = new Date(now.getTime() - days * DAY_MS)
  utimesSync(path, stamp, stamp)
}

describe('deleteStaleRotatedFiles', () => {
  it('removes rotated files older than 14 days and keeps newer ones', () => {
    const dir = mkdtempSync(join(tmpdir(), 'logger-retention-'))
    const logPath = join(dir, 'ui.log')
    const staleNames = ['ui.log.2026-08-22T10-00-00-000Z', 'ui.log.2025-01-01T10-00-00-000Z']
    const freshName = 'ui.log.2026-11-01T10-00-00-000Z'
    makeRotatedFiles(logPath, [staleNames[0], staleNames[1], freshName, 'ui.log'])
    const now = new Date('2026-11-05T01:00:00Z')
    for (const name of staleNames) ageFile(join(dir, name), 30, now)
    ageFile(join(dir, freshName), 4, now)

    const removed = deleteStaleRotatedFiles(logPath, 14, now)

    expect(removed.sort()).toEqual([...staleNames].sort())
    expect(readdirSync(dir).sort()).toEqual(['ui.log', freshName])
  })

  it('never deletes the active log file even when it is old', () => {
    const dir = mkdtempSync(join(tmpdir(), 'logger-retention-'))
    const logPath = join(dir, 'ui.log')
    makeRotatedFiles(logPath, ['ui.log'])
    const now = new Date('2026-11-05T01:00:00Z')
    ageFile(logPath, 365, now)

    const removed = deleteStaleRotatedFiles(logPath, 14, now)

    expect(removed).toEqual([])
    expect(statSync(logPath).size).toBeGreaterThan(0)
  })

  it("ignores unrelated files that don't match the rotation pattern", () => {
    const dir = mkdtempSync(join(tmpdir(), 'logger-retention-'))
    const logPath = join(dir, 'ui.log')
    makeRotatedFiles(logPath, ['ui.log', 'unrelated-old.log', 'ui.log.gz'])
    const now = new Date('2026-11-05T01:00:00Z')
    ageFile(join(dir, 'unrelated-old.log'), 400, now)
    ageFile(join(dir, 'ui.log.gz'), 400, now)

    const removed = deleteStaleRotatedFiles(logPath, 14, now)

    expect(removed).toEqual([])
    expect(readdirSync(dir).sort()).toEqual(['ui.log', 'ui.log.gz', 'unrelated-old.log'].sort())
  })

  it('returns empty when the log directory does not exist', () => {
    const removed = deleteStaleRotatedFiles(join(tmpdir(), `missing-${crypto.randomUUID()}`, 'ui.log'), 14)
    expect(removed).toEqual([])
  })
})
