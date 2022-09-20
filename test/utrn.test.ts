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
import * as utrn from '../src/utrn'
import { keyStore } from './dummy-keystore'

describe('pptd', () => {
  test('defined', () => {
    expect(utrn.pptd)
  })

  test('nominal-pounds', async () => {
    await expect(
      utrn.pptd({
        counter: BigInt(0x100000000),
        originator: '90B3D51F30010000',
        target: '00DB1234567890A0',
        lookupKey: keyStore,
        value: 100,
        valueClass: 'pounds',
      })
    ).resolves.toStrictEqual(BigInt('7394333345718904331'))
  })

  test('nominal-hyphens', async () => {
    await expect(
      utrn.pptd({
        counter: BigInt(0x100000000),
        originator: '90-B3-D5-1F-30-01-00-00',
        target: '00-DB-12-34-56-78-90-A0',
        lookupKey: keyStore,
        value: 100,
        valueClass: 'pounds',
      })
    ).resolves.toStrictEqual(BigInt('7394333345718904331'))
  })

  test('fail-wrong-class', async () => {
    await expect(
      utrn.pptd({
        counter: BigInt(0x100000000),
        originator: '90-B3-D5-1F-30-01-00-00',
        target: '00-DB-12-34-56-78-90-A0',
        lookupKey: keyStore,
        value: 100,
        valueClass: 'pennies',
      })
    ).resolves.not.toStrictEqual(BigInt('7394333345718904331'))
  })

  test('nominal-pennies', async () => {
    await expect(
      utrn.pptd({
        counter: BigInt(0x400000000),
        originator: '90B3D51F30010000',
        target: '00DB1234567890A0',
        lookupKey: keyStore,
        value: 1234,
        valueClass: 'pennies',
      })
    ).resolves.toStrictEqual(BigInt('7394725241674520163'))
  })

  test('nominal-pennies-implicit', async () => {
    await expect(
      utrn.pptd({
        counter: BigInt(0x400000000),
        originator: '90B3D51F30010000',
        target: '00DB1234567890A0',
        lookupKey: keyStore,
        value: 1234,
      })
    ).resolves.toStrictEqual(BigInt('7394725241674520163'))
  })

  test('fail-value-negative', async () => {
    await expect(() =>
      utrn.pptd({
        counter: BigInt(0x100000000),
        originator: '90B3D51F30010000',
        target: '00DB1234567890A0',
        lookupKey: keyStore,
        value: -1,
        valueClass: 'pounds',
      })
    ).rejects.toThrow('value out of range')
  })

  test('fail-value-too-large', async () => {
    await expect(() =>
      utrn.pptd({
        counter: BigInt(0x100000000),
        originator: '90B3D51F30010000',
        target: '00DB1234567890A0',
        lookupKey: keyStore,
        value: 8192,
        valueClass: 'pounds',
      })
    ).rejects.toThrow('value out of range')
  })

  test('nominal-value-max', async () => {
    await expect(
      utrn.pptd({
        counter: BigInt(0x100000000),
        originator: '90B3D51F30010000',
        target: '00DB1234567890A0',
        lookupKey: keyStore,
        value: 8191,
        valueClass: 'pounds',
      })
    ).resolves.toStrictEqual(BigInt('7394368095646343255'))
  })

  test('fail-originator-invalid', async () => {
    await expect(() =>
      utrn.pptd({
        counter: BigInt(0x100000000),
        originator: '90B3D51F30010000d',
        target: '00DB1234567890A0',
        lookupKey: keyStore,
        value: 5,
      })
    ).rejects.toThrow('unexpected originator format')
  })

  test('fail-target-invalid', async () => {
    await expect(() =>
      utrn.pptd({
        counter: BigInt(0x100000000),
        originator: '90B3D51F30010000',
        target: '00DB12_34567890A0',
        lookupKey: keyStore,
        value: 5,
      })
    ).rejects.toThrow('unexpected target format')
  })
})

describe('verhoeff', () => {
  test('defined', () => {
    expect(utrn.verhoeffGbcs).toBeDefined()
  })

  test('reject-empty', () => {
    expect(() => utrn.verhoeffGbcs('')).toThrow(
      'expected input is a string consisting of digits 0-9'
    )
  })

  test('reject-invalid-char', () => {
    expect(() => utrn.verhoeffGbcs('0123adef345')).toThrow(
      'expected input is a string consisting of digits 0-9'
    )
  })
  ;[
    '73943333457189043313',
    '74301825837596672005',
    '73946144332040217315',
    '73947252416745201637',
  ].forEach((digits) => {
    test(`nominal-${digits}`, () => {
      expect(utrn.verhoeffGbcs(digits.slice(0, -1))).toBe(digits.slice(-1))
    })
  })
})

describe('utrn', () => {
  test('defined', () => {
    expect(utrn.utrn).toBeDefined()
  })

  test('nominal-1', () => {
    return expect(
      utrn.utrn({
        counter: BigInt(0x100000000),
        originator: '90B3D51F30010000',
        target: '00DB1234567890A0',
        lookupKey: keyStore,
        value: 100,
        valueClass: 'pounds',
      })
    ).resolves.toStrictEqual('73943333457189043313')
  })

  test('nominal-2', () => {
    return expect(
      utrn.utrn({
        counter: BigInt(0x400000000),
        originator: '90B3D51F30010000',
        target: '00DB1234567890A0',
        lookupKey: keyStore,
        value: 1234,
        valueClass: 'pennies',
      })
    ).resolves.toStrictEqual('73947252416745201637')
  })
})
