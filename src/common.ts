/*
 *
 * Original copyright holders for the GBCS message parser tool:
 *
 * Copyright (c) 2019 Andre B. Oliveira
 *               2019 Enrique Giraldo
 *               2019 Cristóbal Borrero
 *
 * Copyright for subsequent changes, including porting to NodeJS,
 * updating for TypeScript and refactor to support unit testing:
 *
 * Copyright (c) 2022 Smart DCC Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import { Context, putBytes } from './context'
import { getBytes, getDecimalString, messageCodes, Slice } from './util'

export function parseNumber(x: Slice, size: number, offset?: number) {
  // XXX Max safe integer in JavaScript is 2^53-1, can't handle size > 6
  offset = offset ?? 0
  let value = 0
  for (let i = 0; i < size; i++) {
    value *= 0x100
    value += x.input[x.index + offset + i]
  }
  return value
}

export function parseNumberLE(x: Slice, size: number, offset?: number) {
  // XXX Max safe integer in JavaScript is 2^53-1, can't handle size > 6
  offset = offset ?? 0
  let value = 0
  for (let i = size; i > 0; i--) {
    value *= 0x100
    value += x.input[x.index + offset + i - 1]
  }
  return value
}

export function parseLength(x: Slice, offset?: number) {
  offset = offset ?? 0
  let len = x.input[x.index + offset]
  let size = 1
  if (len & 0x80) {
    // Multi-byte length, limit to 3 bytes
    size += len & 3
    len = parseNumber(x, len & 3, offset + 1)
  }
  return { length: len, size: size }
}

export function parseMessageCode(ctx: Context, name: string, x: Slice) {
  const messageCode = parseNumber(x, 2)
  putBytes(ctx, name, getBytes(x, 2), messageCodes[messageCode])
  return messageCode
}

export function parseCounter(ctx: Context, name: string, x: Slice) {
  const bytes = getBytes(x, 8)
  putBytes(ctx, name, bytes, getDecimalString(bytes))
}

export function parseMeterIntegrityIssueWarning(ctx: Context, x: Slice) {
  const otherInfo = parseNumber(x, 2)
  const names: Record<number, string> = {
    0x0000: 'Other',
    0x0001: 'Error Non Volatile Memory',
    0x0002: 'Error Program Execution',
    0x0003: 'Error Program Storage',
    0x0004: 'Error RAM',
    0x0005: 'Error Unexpected Hardware Reset',
    0x0006: 'Error Watchdog',
    0x0007: 'Error Metrology Firmware Verification Failure',
    0x0008: 'Error Measurement Fault',
    0x0009: 'Unspecified Smart Meter Operational Integrity Error',
  }
  putBytes(ctx, 'Other Info', getBytes(x, 2), names[otherInfo])
}

export function parseCraFlag(ctx: Context, x: Slice) {
  const craFlag = x.input[x.index]
  putBytes(
    ctx,
    'CRA Flag',
    getBytes(x, 1),
    { 1: 'Command', 2: 'Response', 3: 'Alert' }[craFlag] || 'INVALID'
  )
  return craFlag
}
