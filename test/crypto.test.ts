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

import { createSecretKey } from 'crypto'
import * as crypto from '../src/crypto'

describe('gcm', () => {
  test('is defined', () => {
    expect(crypto.gcm).toBeDefined()
  })

  test('nominal-aad-only', () => {
    expect(
      crypto.gcm(
        {
          origCounter: Buffer.from('0102030405060708', 'hex'),
          origSysTitle: Buffer.from('90b3d51f30030000', 'hex'),
          recipSysTitle: Buffer.from('00db1234567890a1', 'hex'),
        },
        Buffer.from([]),
        Buffer.from('helloworld', 'ascii'),
        createSecretKey('000102030405060708090a0b0c0d0e0f', 'hex')
      )
    ).toStrictEqual({
      cipherText: Buffer.from([]),
      tag: Buffer.from('fb3afed43b78508864f00da3', 'hex'),
    })
  })

  test('nominal-aad-only-short', () => {
    expect(
      crypto.gcm(
        {
          origCounter: Buffer.from('0102030405060708', 'hex'),
          origSysTitle: Buffer.from('90b3d51f30030000', 'hex'),
          recipSysTitle: Buffer.from('00db1234567890a1', 'hex'),
        },
        Buffer.from([]),
        Buffer.from('helloworld', 'ascii'),
        createSecretKey('000102030405060708090a0b0c0d0e0f', 'hex'),
        4
      )
    ).toStrictEqual({
      cipherText: Buffer.from([]),
      tag: Buffer.from('fb3afed4', 'hex'),
    })
  })

  test('nominal', () => {
    expect(
      crypto.gcm(
        {
          origCounter: Buffer.from('0102030405060708', 'hex'),
          origSysTitle: Buffer.from('90b3d51f30030000', 'hex'),
          recipSysTitle: Buffer.from('00db1234567890a1', 'hex'),
        },
        Buffer.from('one two three', 'ascii'),
        Buffer.from('helloworld', 'ascii'),
        createSecretKey('000102030405060708090a0b0c0d0e0f', 'hex')
      )
    ).toStrictEqual({
      cipherText: Buffer.from('584fa806b24491178829d46c38', 'hex'),
      tag: Buffer.from('6b33bdcb1e223242ec20b957', 'hex'),
    })
  })
})
