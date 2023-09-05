/*
 * Created on Tue Aug 01 2023
 *
 * Copyright (c) 2023 Smart DCC Limited
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

import { readFileSync } from 'node:fs'

import { parseGbcsMessage } from '../src/parser'
import { keyStore } from './dummy-keystore'
import { minimizeMessage } from '../src/context'

import { decodeECS24, decodeDLMSDateTime, minifyList } from '../src/tariff'

describe('decodeDLMSDateTime', () => {
  const logger = jest.fn()

  afterEach(() => {
    logger.mockReset()
  })

  test('wrong-size-buffer', () => {
    expect(
      decodeDLMSDateTime(Buffer.from('07de0813ffffffffffffff', 'hex'), logger),
    ).toBeNull()
    expect(logger).toBeCalledWith(expect.stringContaining('bytes'))
  })

  test('daylight_savings_end not supported', () => {
    expect(
      decodeDLMSDateTime(Buffer.from('fffffdffff', 'hex'), logger),
    ).toBeNull()
    expect(logger).toBeCalledWith(
      expect.stringContaining('daylight_savings_end'),
    )
  })

  test('daylight_savings_begin not supported', () => {
    expect(
      decodeDLMSDateTime(Buffer.from('fffffeffff', 'hex'), logger),
    ).toBeNull()
    expect(logger).toBeCalledWith(
      expect.stringContaining('daylight_savings_begin'),
    )
  })

  test('non-zero-date-time not supported', () => {
    expect(
      decodeDLMSDateTime(
        Buffer.from('07de0813ff010203040000ff', 'hex'),
        logger,
      ),
    ).toBeNull()
    expect(logger).toBeCalledWith(expect.stringContaining('time should be 0'))
  })

  test('non-utc-date-time not supported', () => {
    expect(
      decodeDLMSDateTime(
        Buffer.from('07de0813ff000000000100ff', 'hex'),
        logger,
      ),
    ).toBeNull()
    expect(logger).toBeCalledWith(expect.stringContaining('should be in UTC'))
  })

  test('specified-clock-status not supported', () => {
    expect(
      decodeDLMSDateTime(
        Buffer.from('07de0813ff00000000000001', 'hex'),
        logger,
      ),
    ).toBeNull()
    expect(logger).toBeCalledWith(expect.stringContaining('clock status'))
  })

  describe('dlms-nominal', () => {
    ;[
      { name: 'datetime/utc', append: '000000000000ff' },
      { name: 'datetime/non-specified', append: '000000008000ff' },
      { name: 'date', append: '' },
    ].map(({ name, append }) => {
      describe(name, () => {
        test('absolute', () => {
          expect(
            decodeDLMSDateTime(
              Buffer.from(`07de0813ff${append}`, 'hex'),
              logger,
            ),
          ).toStrictEqual({
            year: 2014,
            month: 8,
            dayOfMonth: 19,
          })
          expect(logger).not.toBeCalled()
        })

        test('last-day-of-the-month-in-every-year-and-month', () => {
          expect(
            decodeDLMSDateTime(
              Buffer.from(`fffffffeff${append}`, 'hex'),
              logger,
            ),
          ).toStrictEqual({
            dayOfMonth: 0xfe,
          })
          expect(logger).not.toBeCalled()
        })

        test('last-sunday-in-every-year-and-month', () => {
          expect(
            decodeDLMSDateTime(
              Buffer.from(`fffffffe07${append}`, 'hex'),
              logger,
            ),
          ).toStrictEqual({
            dayOfMonth: 0xfe,
            dayOfWeek: 7,
          })
          expect(logger).not.toBeCalled()
        })

        test('last-sunday-in-march-in-every-year', () => {
          expect(
            decodeDLMSDateTime(
              Buffer.from(`ffff03fe07${append}`, 'hex'),
              logger,
            ),
          ).toStrictEqual({
            month: 3,
            dayOfMonth: 0xfe,
            dayOfWeek: 7,
          })
          expect(logger).not.toBeCalled()
        })

        test('forth-friday-in-march-in-every-year', () => {
          expect(
            decodeDLMSDateTime(
              Buffer.from(`ffff031605${append}`, 'hex'),
              logger,
            ),
          ).toStrictEqual({
            month: 3,
            dayOfMonth: 22,
            dayOfWeek: 5,
          })
          expect(logger).not.toBeCalled()
        })

        test('forth-sunday-in-october-in-every-year', () => {
          expect(
            decodeDLMSDateTime(
              Buffer.from(`ffff0a1607${append}`, 'hex'),
              logger,
            ),
          ).toStrictEqual({
            month: 10,
            dayOfMonth: 22,
            dayOfWeek: 7,
          })
          expect(logger).not.toBeCalled()
        })
      })
    })
  })
})

describe('minifyList', () => {
  test('with zeros', () => {
    expect(minifyList([0, 1, 2, 3, 0, 0, 0])).toStrictEqual([0, 1, 2, 3])
  })

  test('without zeros', () => {
    expect(minifyList([0, 1, 2, 3])).toStrictEqual([0, 1, 2, 3])
  })

  test('all zeros', () => {
    expect(minifyList([0, 0, 0, 0])).toStrictEqual([])
  })

  test('empty', () => {
    expect(minifyList([])).toStrictEqual([])
  })

  test('big', () => {
    expect(minifyList([1, ...Array<number>(1024).fill(0)])).toStrictEqual([1])
  })
})

describe('decodeECS24', () => {
  describe('rtds', () => {
    test('ECS17b_4.1.1_SINGLE_SUCCESS_RESPONSE is null', async () => {
      const logger = jest.fn()
      const message = readFileSync(
        'test/rtds/RTDS-4.5.0/4.1.1_ECS17b/ECS17b_4.1.1_SINGLE_SUCCESS_RESPONSE_GBCS.HEX',
        'utf-8',
      )
      const output = minimizeMessage(await parseGbcsMessage(message, keyStore))

      expect(decodeECS24(output, logger)).toBeNull()
      expect(logger).toBeCalledWith(expect.stringContaining('message code'))
    })

    test('ECS24_4.11.1_SUCCESS_COMMAND is null', async () => {
      const logger = jest.fn()
      const message = readFileSync(
        'test/rtds/RTDS-4.5.0/4.11.1_ECS24/ECS24_4.11.1_SUCCESS_COMMAND_GBCS.HEX',
        'utf-8',
      )
      const output = minimizeMessage(await parseGbcsMessage(message, keyStore))

      expect(decodeECS24(output, logger)).toBeNull()
      expect(logger).toBeCalledWith(expect.stringContaining('response'))
    })

    test('ECS24_4.11.1_ERROR_RESPONSE is null', async () => {
      const logger = jest.fn()
      const message = readFileSync(
        'test/rtds/RTDS-4.5.0/4.11.1_ECS24/ECS24_4.11.1_ERROR_RESPONSE_GBCS.HEX',
        'utf-8',
      )
      const output = minimizeMessage(await parseGbcsMessage(message, keyStore))

      expect(decodeECS24(output, logger)).toBeNull()
      expect(logger).toBeCalledTimes(3)
      expect(logger).toBeCalledWith(expect.stringContaining('not successful'))
      expect(logger).toBeCalledWith(
        expect.stringContaining('[15] Access Response Specification'),
      )
      expect(logger).toBeCalledWith(
        expect.stringContaining('[16] Access Response Specification'),
      )
    })

    test('ECS24_4.11.1_SUCCESS_RESPONSE is ok', async () => {
      const logger = jest.fn()
      const message = readFileSync(
        'test/rtds/RTDS-4.5.0/4.11.1_ECS24/ECS24_4.11.1_SUCCESS_RESPONSE_GBCS.HEX',
        'utf-8',
      )
      const output = minimizeMessage(await parseGbcsMessage(message, keyStore))

      expect(decodeECS24(output, logger)).toMatchObject({
        seasons: [
          {
            name: 'all',
            weekProfile: 1,
            year: 2015,
            month: 1,
            dayOfMonth: 1,
          },
        ],
        weekProfiles: [[1, 1, 1, 1, 1, 2, 2]],
        dayProfiles: [
          [
            {
              mode: 'block',
              startTime: 25200,
              action: 1,
            },
            {
              mode: 'block',
              startTime: 82800,
              action: 2,
            },
          ],
          [
            {
              mode: 'tou',
              startTime: 0,
              action: 1,
            },
          ],
        ],
        specialDays: [
          {
            dayProfile: 2,
            dayOfMonth: 1,
            month: 5,
            year: 2015,
          },
          {
            dayProfile: 2,
            dayOfMonth: 25,
            month: 12,
            year: 2015,
          },
        ],
        pricing: {
          priceScale: -5,
          standingCharge: 20000,
          standingChargeScale: -5,
        },
        tous: [2121],
        blocks: [
          {
            prices: [2289, 3546, 0, 0],
            thresholds: [10000, 4294967295, 4294967295],
          },
          {
            prices: [4002, 6969, 0, 0],
            thresholds: [10000, 4294967295, 4294967295],
          },
          {
            prices: [0, 0, 0, 0],
            thresholds: [4294967295, 4294967295, 4294967295],
          },
          {
            prices: [0, 0, 0, 0],
            thresholds: [4294967295, 4294967295, 4294967295],
          },
          {
            prices: [0, 0, 0, 0],
            thresholds: [4294967295, 4294967295, 4294967295],
          },
          {
            prices: [0, 0, 0, 0],
            thresholds: [4294967295, 4294967295, 4294967295],
          },
          {
            prices: [0, 0, 0, 0],
            thresholds: [4294967295, 4294967295, 4294967295],
          },
          {
            prices: [0, 0, 0, 0],
            thresholds: [4294967295, 4294967295, 4294967295],
          },
        ],
      })
      expect(logger).toBeCalledTimes(1)
    })
  })

  test('hybrid', async () => {
    const logger = jest.fn()
    const message =
      '3QAAAAAAAIIEFhEAAAAA3wkCAAABikV8U1MIHMEbsQAAHQIIkLPVHzABAAAAAgA6ggPg2iB8U1MAABEGAA9CQAICD/sW/gECAgMJBnN1bW1lcgkM//8E//8AAAAAgAD/CQEBAgMJBndpbnRlcgkM//8K//8AAAAAgAD/CQEBAQECCAkBAREBEQERAREBEQERAhECAQICAhEBAQECAwkEAAAAAAkGAAAKAGT/EgBlAgIRAgEDAgMJBAAAAAAJBgAACgBk/xIAAgIDCQQNAAAACQYAAAoAZP8SAAECAwkEEwAAAAkGAAAKAGT/EgACAQECAxIAAQkF//8CGf8RAgEBBgAAAAEBAQYAAAAAAQEGAAAAAAEBBgAAAAABAQYAAAAAAQEGAAAAAAEBBgAAAAABAQYAAAAAAwECAwICDwAPAAIDEgAACQYAAAAAAAAPAAEBAgIJABAACgIDAgIPAw/9AgMSAAMJBgEAAQgA/w8CAVACAgkBARAnEAICCQECEAH0AgIJAQMQAAACAgkBBBAAAAICCQEFEAAAAgIJAQYQAAACAgkBBxAAAAICCQEIEAAAAgIJAQkQAAACAgkBChAAAAICCQELEAAAAgIJAQwQAAACAgkBDRAAAAICCQEOEAAAAgIJAQ8QAAACAgkBEBAAAAICCQEREAAAAgIJARIQAAACAgkBExAAAAICCQEUEAAAAgIJARUQAAACAgkBFhAAAAICCQEXEAAAAgIJARgQAAACAgkBGRAAAAICCQEaEAAAAgIJARsQAAACAgkBHBAAAAICCQEdEAAAAgIJAR4QAAACAgkBHxAAAAICCQEgEAAAAgIJASEQAAACAgkBIhAAAAICCQEjEAAAAgIJASQQAAACAgkBJRAAAAICCQEmEAAAAgIJAScQAAACAgkBKBAAAAICCQEpEAAAAgIJASoQAAACAgkBKxAAAAICCQEsEAAAAgIJAS0QAAACAgkBLhAAAAICCQEvEAAAAgIJATAQAAACAgkBoRAnEAICCQGiEAAAAgIJAaMQAAACAgkBpBAAAAICCQGlEAAAAgIJAaYQAAACAgkBpxAAAAICCQGoEAAAAgIJAbEQE4gCAgkBshAAAAICCQGzEAAAAgIJAbQQAAACAgkBtRAAAAICCQG2EAAAAgIJAbcQAAACAgkBuBAAAAICCQHBEAAAAgIJAcIQAAACAgkBwxAAAAICCQHEEAAAAgIJAcUQAAACAgkBxhAAAAICCQHHEAAAAgIJAcgQAAACAgkB0RAAAAICCQHSEAAAAgIJAdMQAAACAgkB1BAAAAICCQHVEAAAAgIJAdYQAAACAgkB1xAAAAICCQHYEAAAEQEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQAAgjflG1L9gH6vni+7'
    const output = minimizeMessage(await parseGbcsMessage(message, keyStore))
    expect(decodeECS24(output, logger)).toMatchObject({
      seasons: [
        { name: 'summer', weekProfile: 1, month: 4 },
        { name: 'winter', weekProfile: 1, month: 10 },
      ],
      weekProfiles: [[1, 1, 1, 1, 1, 2, 2]],
      dayProfiles: [
        [{ startTime: 0, action: 1, mode: 'block' }],
        [
          { startTime: 0, action: 2, mode: 'tou' },
          { startTime: 46800, action: 1, mode: 'tou' },
          { startTime: 68400, action: 2, mode: 'tou' },
        ],
      ],
      specialDays: [{ month: 2, dayOfMonth: 25, dayProfile: 2 }],
      pricing: { priceScale: -3, standingCharge: 10, standingChargeScale: 0 },
      tous: [10000, 500],
      blocks: [
        { thresholds: [1], prices: [10000, 5000] },
        { thresholds: [0], prices: [0, 0] },
        { thresholds: [0], prices: [0, 0] },
        { thresholds: [0], prices: [0, 0] },
        { thresholds: [0], prices: [0, 0] },
        { thresholds: [0], prices: [0, 0] },
        { thresholds: [0], prices: [0, 0] },
        { thresholds: [0], prices: [0, 0] },
      ],
    })
    expect(logger).toBeCalledTimes(2) /* once for each season */
  })
})
