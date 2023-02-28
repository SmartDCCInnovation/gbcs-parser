/*
 * Created on Thu Sep 15 2022
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

import { readFile } from 'node:fs/promises'
import { KeyStore } from '../src/context'
import { createPrivateKey, createPublicKey, KeyObject } from 'crypto'
import glob from 'glob'

const globP = (f: string) => glob(f)

const keyStoreCache: {
  eui: string
  type: 'KA' | 'DS'
  privateKey: boolean
  prePayment: boolean
  key: KeyObject
}[] = []

export const keyStore: KeyStore = async (
  eui,
  type,
  { privateKey, prePayment }
) => {
  if (typeof eui === 'object') {
    eui = Buffer.from(eui).toString('hex')
  }
  eui = eui.replaceAll('-', '').replaceAll(' ', '').toLowerCase()
  privateKey = privateKey ?? false
  prePayment = prePayment ?? false

  const ce = keyStoreCache.find(
    (e) => e.eui === eui && e.type === type && e.privateKey === privateKey
  )
  if (ce) {
    return ce.key
  }

  const fileName = `${eui}${prePayment ? '-pp' : ''}-${type.toLowerCase()}.${
    privateKey ? 'key' : 'pem'
  }`
  const keyFiles = await globP(`**/${fileName}`)
  if (keyFiles.length !== 1) {
    throw new Error(`could not locate key file: ${fileName}`)
  }

  const pem = await readFile(keyFiles[0], 'utf-8')
  let key: KeyObject
  if (privateKey) {
    key = createPrivateKey(pem)
  } else {
    key = createPublicKey(pem)
  }

  keyStoreCache.push({
    eui,
    type,
    privateKey,
    prePayment,
    key,
  })

  return key
}
