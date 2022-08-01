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

import { KeyObject } from 'crypto'
import { Slice } from './util'

export interface CipherInfo {
  origCounter: Uint8Array
  origSysTitle: Uint8Array
  recipSysTitle: Uint8Array
}

export interface ParsedItem {
  type: 'ITEM'
  depth: number
  hex: string
  notes?: string
  children?: { [key: string]: ParsedItem }
}
export interface ParsedBlock {
  type: 'SEPARATOR'
  depth: number
  children: { [key: string]: ParsedItem }
}
export interface ParsedMessage {
  [key: string]: ParsedBlock
}
export type KeyStore = (
  eui: string | Uint8Array,
  type: 'KA' | 'DS',
  privateKey?: boolean
) => Promise<KeyObject>

export type DecryptCB = (cipherInfo: CipherInfo, aesKey: KeyObject) => void

export interface Context {
  lookupKey: KeyStore
  output: ParsedMessage
  current: (
    | ParsedBlock
    | ParsedItem
  )[] /* internal state, should not be touched outside of this file */
  decryptionList: DecryptCB[]
}

export function putSeparator(ctx: Context, title: string) {
  const sep: ParsedBlock = {
    type: 'SEPARATOR',
    depth: 0,
    children: {},
  }
  if (title in ctx.output) {
    throw new Error(`overwrite output ${title}`)
  }
  ctx.current = [sep]
  ctx.output[title] = sep
}

export function putBytes(
  ctx: Context,
  name: string,
  bytes: Slice,
  notes?: string
) {
  const h = '0123456789ABCDEF'
  const n = bytes.end - bytes.index
  let hex = ''
  for (let i = 0; i < n; i++) {
    if (i > 0) {
      hex += ' '
    }
    const b = bytes.input[bytes.index++]
    hex += h.charAt((b >> 4) & 15) + h.charAt(b & 15)
  }

  const result = name.match(/^ */)
  const depth = (result?.[0].length ?? 0) + 1
  const item: ParsedItem = {
    type: 'ITEM',
    depth,
    hex,
    notes,
  }

  /* pop off item deeper or equal */
  while (ctx.current[ctx.current.length - 1].depth >= depth) {
    ctx.current.pop()
  }

  if (
    depth > 1 &&
    (ctx.current[ctx.current.length - 1].type === 'SEPARATOR' ||
      depth !== ctx.current[ctx.current.length - 1].depth + 1)
  ) {
    throw new Error(`incorrect nesting ${name}`)
  }

  const parent = ctx.current[ctx.current.length - 1]
  if (parent.children === undefined) {
    parent.children = {}
  }
  if (name.trimStart() in parent.children) {
    throw new Error(`overwrite output ${name}`)
  }
  parent.children[name.trimStart()] = item
  ctx.current.push(item)
}

export function putUnparsedBytes(bytes: Slice) {
  if (bytes.end - bytes.index > 0) {
    throw new Error(`unexpected data ${bytes}`)
  }
}

export interface MinimizedParsedItem {
  hex: string
  notes?: string
  children?: { [key: string]: MinimizedParsedItem }
}
export interface MinimizedParsedBlock {
  [key: string]: MinimizedParsedItem
}
export interface MinimizedParsedMessage {
  [key: string]: MinimizedParsedBlock
}

export function minimizeItem({
  hex,
  notes,
  children,
}: ParsedItem): MinimizedParsedItem {
  const result: MinimizedParsedItem = {
    hex,
  }
  if (notes) {
    result.notes = notes
  }
  if (children && Object.keys(children).length >= 1) {
    result.children = Object.fromEntries(
      Object.keys(children).map((k) => [k, minimizeItem(children[k])])
    )
  }
  return result
}

export function minimizeBlock({ children }: ParsedBlock): MinimizedParsedBlock {
  return Object.fromEntries(
    Object.keys(children).map((k) => [k, minimizeItem(children[k])])
  )
}

/**
 * Removes files from ParsedMessage structure that are only relevant for
 * internal use.
 *
 * @param message
 * @returns
 */
export function minimizeMessage(
  message: ParsedMessage
): MinimizedParsedMessage {
  return Object.fromEntries(
    Object.keys(message).map((k) => [k, minimizeBlock(message[k])])
  )
}
