/**
 * MSW server instance for Node.js / Vitest test environment.
 *
 * Import this in test setup files to intercept outgoing HTTP
 * requests with the handlers defined in `./handlers.ts`.
 */
import { setupServer } from 'msw/node'

import { handlers } from './handlers'

export const server = setupServer(...handlers)
