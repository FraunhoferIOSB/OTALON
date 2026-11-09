/**
 * Shared pino logger for the Nitro server.
 *
 * Writes structured JSON logs to both a rotating file and stdout
 * (for container log capture). Uses pino.multistream() instead of
 * pino transports to avoid worker-thread module resolution issues
 * in Nitro's bundled production output.
 *
 * The file path and log level are configurable via LOG_FILE
 * (or UI_NEXT_LOG_FILE) and LOG_LEVEL environment variables. Rotated
 * files older than UI_LOG_RETENTION_DAYS (default 14) days are pruned
 * on rotation.
 */

import pino from 'pino'
import * as fs from 'node:fs'
import { createWriteStream, existsSync, mkdirSync, readdirSync, renameSync, statSync, unlinkSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'

const LOG_FILE = process.env.LOG_FILE || process.env.UI_NEXT_LOG_FILE || join(process.cwd(), 'logs', 'ui-next.log')
const LOG_LEVEL = process.env.LOG_LEVEL || 'info'
const MAX_FILE_BYTES = 10 * 1024 * 1024
const RETENTION_DAYS = Number(process.env.UI_LOG_RETENTION_DAYS || 14)

/**
 * Create a writable file stream for the given path, ensuring
 * parent directories exist.
 */
function openLogStream(filePath: string): ReturnType<typeof createWriteStream> {
  const dir = dirname(filePath)
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true })
  }
  return createWriteStream(filePath, { flags: 'a' })
}

let fileStream = openLogStream(LOG_FILE)

const ROTATED_SUFFIX_RE = /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z$/

/**
 * Delete rotated log files older than the retention window.
 *
 * Only files matching the rotation pattern ``${LOG_FILE}.<timestamp>``
 * are considered; the active log file and unrelated files are never
 * touched. Exposed for tests.
 *
 * @param filePath Base log file path whose rotated siblings are pruned.
 * @param retentionDays Maximum age (in days) for a rotated file.
 * @param now Reference time; older rotations are removed. Defaults to
 *   the current time.
 * @returns Names of the removed rotation files (basename relative to
 *   the log directory).
 */
export function deleteStaleRotatedFiles(filePath: string, retentionDays: number, now: Date = new Date()): string[] {
  const dir = dirname(filePath)
  const prefix = `${basename(filePath)}.`
  const cutoffMs = now.getTime() - retentionDays * 24 * 60 * 60 * 1000
  const removed: string[] = []

  let entries: string[]
  try {
    entries = readdirSync(dir)
  } catch {
    return removed
  }

  for (const entry of entries) {
    if (!entry.startsWith(prefix)) continue
    if (!ROTATED_SUFFIX_RE.test(entry.slice(prefix.length))) continue
    const entryPath = join(dir, entry)
    let mtimeMs: number
    try {
      mtimeMs = statSync(entryPath).mtimeMs
    } catch {
      continue
    }
    if (mtimeMs < cutoffMs) {
      try {
        unlinkSync(entryPath)
        removed.push(entry)
      } catch {
        /* retention best-effort — file may have been removed externally */
      }
    }
  }
  return removed
}

/**
 * Rotate the log file when it exceeds MAX_FILE_BYTES.
 * Renames the current file with a timestamp suffix, prunes rotated
 * files older than RETENTION_DAYS and opens a fresh stream.
 */
function rotateIfNeeded(): void {
  let size: number
  try {
    size = statSync(LOG_FILE).size
  } catch {
    return
  }
  if (size < MAX_FILE_BYTES) return

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
  const rotatedPath = `${LOG_FILE}.${timestamp}`

  fileStream.end()

  try {
    renameSync(LOG_FILE, rotatedPath)
  } catch {
    /* rotation best-effort — file may have been removed externally */
  }

  deleteStaleRotatedFiles(LOG_FILE, RETENTION_DAYS)

  fileStream = openLogStream(LOG_FILE)
  const fileEntry = multiStream.streams.find((entry) => entry.stream instanceof fs.WriteStream)
  if (fileEntry) fileEntry.stream = fileStream
}

const multiStream = pino.multistream([
  { level: LOG_LEVEL as pino.Level, stream: fileStream },
  { level: LOG_LEVEL as pino.Level, stream: process.stdout },
])

export const logFilePath = LOG_FILE

export const logger = pino(
  {
    level: LOG_LEVEL,
    hooks: {
      logMethod(inputArgs, method) {
        const result = method.apply(this, inputArgs as Parameters<typeof method>)
        rotateIfNeeded()
        return result
      },
    },
  },
  multiStream,
)
