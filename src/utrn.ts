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

import { KeyStore, CipherInfo } from './context'
import { deriveKeyFromPair, gcm } from './crypto'

/**
 * constant value used to offset PTUT
 */
const base = BigInt('7394156990786306048')

export interface PtutOptions {
  /**
   * how to interpret the value. if omitted, defaults to pennies.
   */
  valueClass?: 'pennies' | 'pounds'

  /**
   * positive integer between 0 and 8191 - inclusive
   */
  value: number

  /**
   * keystore to lookup certificates/keys for computing the gmac
   */
  lookupKey: KeyStore

  /**
   * originator id
   */
  originator: string

  /**
   * target id
   */
  target: string

  /**
   * counter used to sign message, should be larger than any other counter used
   * for originator/target pair top-ups.
   */
  counter: bigint
}

async function ptut(options: PtutOptions): Promise<bigint> {
  if (
    !Number.isInteger(options.value) ||
    options.value < 0 ||
    options.value > 8191
  ) {
    throw new Error(`value out of range: 0 <= ${options.value} <= 8191`)
  }
  const ctrTruncated = (options.counter >> BigInt(32))
    .toString(2)
    .padStart(10, '0')
    .slice(-10)
  const valueClass = options.valueClass === 'pounds' ? '01' : '00'
  const value = Number(options.value).toString(2).padStart(13, '0').slice(-13)
  const ptut_high_dword = BigInt(
    `0b0000000${ctrTruncated}${valueClass}${value}`,
  )

  const originator = options.originator.replace(/[- ]/g, '').toLowerCase()
  const target = options.target.replace(/[- ]/g, '').toLowerCase()

  if (originator.match(/^[a-f0-9]{16}$/) === null) {
    throw new Error(`unexpected originator format: ${options.originator}`)
  }

  if (target.match(/^[a-f0-9]{16}$/) === null) {
    throw new Error(`unexpected target format: ${options.target}`)
  }

  const aad = Buffer.from(
    `110000000000${originator}${target}01${options.counter
      .toString(16)
      .padStart(16, '0')
      .slice(-16)}${ptut_high_dword.toString(16).padStart(8, '0').slice(-8)}`,
    'hex',
  )

  const cipherInfo: CipherInfo = {
    origSysTitle: Buffer.from(originator, 'hex'),
    recipSysTitle: Buffer.from(target, 'hex'),
    origCounter: Buffer.from(
      BigInt(options.counter).toString(16).padStart(16, '0').slice(-16),
      'hex',
    ),
  }
  /* retrieve device public ka key */
  const pubKey = await options.lookupKey(cipherInfo.recipSysTitle, 'KA', {})
  /* retrieve supplier private pp ka key */
  const prvKey = await options.lookupKey(cipherInfo.origSysTitle, 'KA', {
    privateKey: true,
    prePayment: true,
  })

  const secretKey = deriveKeyFromPair(prvKey, pubKey, cipherInfo, 'command')

  const { tag } = gcm(cipherInfo, Buffer.from([]), aad, secretKey, 16)

  let ptut_low_dword = BigInt(0)
  tag.slice(-4).forEach((b) => {
    ptut_low_dword <<= BigInt(8)
    ptut_low_dword |= BigInt(b)
  })

  return (ptut_high_dword << BigInt(32)) | ptut_low_dword
}

/**
 * generates a pre-payment token decimal in accordance with section 14 of gbcs
 *
 * @param options
 * @returns bigint
 */
export async function pptd(options: PtutOptions): Promise<bigint> {
  return base + (await ptut(options))
}

/**
 * GBCS table 14.8a - permutation table
 */
const P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

/**
 * GBCS table 14.8b - multiplication table
 */
const D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

/**
 * GBCS table 14.8c - inverse table (note this is different from standard
 * Verhoeff in Wiki)
 */
const I = [1, 2, 6, 7, 5, 8, 3, 0, 9, 4]

/**
 * Computes the Verhoeff check digit as described in section 14.8 of GBCS.
 *
 * @param digits non empty string consisting of digits 0-9
 * @returns single digit as string
 */
export function verhoeffGbcs(
  digits: string,
): '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' {
  if (digits.match(/^\d+$/) === null) {
    throw new Error(
      `expected input is a string consisting of digits 0-9, received: ${digits}`,
    )
  }
  let IntDig = 0
  let K = 4
  for (let J = 0; J < digits.length; J++) {
    const CurDig = Number(digits[J])
    const L = P[K][CurDig]
    K = (K + 1) % 8
    IntDig = D[IntDig][L]
  }
  IntDig = I[IntDig]
  return IntDig.toString() as
    | '0'
    | '1'
    | '2'
    | '3'
    | '4'
    | '5'
    | '6'
    | '7'
    | '8'
    | '9'
}

/**
 * applies check digit (Verhoeff algorithm) to pptd
 *
 * @param options
 * @returns complete utrn as string
 */
export async function utrn(options: PtutOptions): Promise<string> {
  const _pptd = (await pptd(options)).toString()
  return `${_pptd}${verhoeffGbcs(_pptd.toString())}`
}
