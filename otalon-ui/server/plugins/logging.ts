/**
 * Nitro plugin that configures server-wide request and error logging.
 *
 * Logs a startup message with the configured log file path,
 * debug-level entries for every incoming request, and error-level
 * entries for unhandled server errors.
 */

import { logger, logFilePath } from '../utils/logger'

export default defineNitroPlugin((nitroApp) => {
  logger.info({ logFile: logFilePath }, 'Nitro server starting — file logging configured')

  nitroApp.hooks.hook('request', (event) => {
    const method = event.method
    const url = event.path
    logger.debug({ method, url }, 'incoming request')
  })

  nitroApp.hooks.hook('error', (error) => {
    logger.error({ err: error }, 'unhandled server error')
  })
})
