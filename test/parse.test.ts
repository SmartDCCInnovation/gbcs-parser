/*
 * Created on Wed Dec 07 2022
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

import { parseGbcsMessage } from '../src/parser'
import { keyStore } from './dummy-keystore'

describe('parse', () => {
  describe('precommand', () => {
    test('missing signature', async () => {
      const message = `
      DF 09 01 00 00 00 00 00 00 03 E9 08 90 B3 D5 1F
      30 01 00 00 08 00 DB 12 34 56 78 90 A0 00 02 00
      62 6C D9 20 00 03 E9 00 05 02 00 08 00 00 01 00
      00 FF 09 03 00 08 00 00 01 00 00 FF 05 03 00 08
      00 00 01 00 00 FF 04 01 00 08 00 00 01 00 00 FF
      02 01 00 08 00 00 01 00 00 FF 04 05 16 05 02 03
      09 0C FF FF FF FF FF FF FF FF FF 80 00 FF 09 0C
      07 DE 0C 1F FF 17 3B 0A 00 80 00 FF 09 0C 07 DF
      01 01 FF 00 00 0A 00 80 00 FF 0F 00 00 00
      `
      const output = await parseGbcsMessage(message, keyStore)
      expect('Grouping Header' in output).toBeTruthy()
      expect('Payload' in output).toBeTruthy()
      expect('Signature' in output).toBeFalsy()
    })

    test('nominal', async () => {
      const message = `
      DF 09 01 00 00 00 00 00 00 03 E9 08 90 B3 D5 1F
      30 01 00 00 08 00 DB 12 34 56 78 90 A0 00 02 00
      62 6C D9 20 00 03 E9 00 05 02 00 08 00 00 01 00
      00 FF 09 03 00 08 00 00 01 00 00 FF 05 03 00 08
      00 00 01 00 00 FF 04 01 00 08 00 00 01 00 00 FF
      02 01 00 08 00 00 01 00 00 FF 04 05 16 05 02 03
      09 0C FF FF FF FF FF FF FF FF FF 80 00 FF 09 0C
      07 DE 0C 1F FF 17 3B 0A 00 80 00 FF 09 0C 07 DF
      01 01 FF 00 00 0A 00 80 00 FF 0F 00 00 00 00
      `
      const output = await parseGbcsMessage(message, keyStore)
      expect('Grouping Header' in output).toBeTruthy()
      expect('Payload' in output).toBeTruthy()
      expect('Signature' in output).toBeTruthy()
      expect(output['Signature'].children['Signature Length'].hex).toBe('00')
    })
  })

  describe('malformed', () => {
    test('wrong-signature-length', async () => {
      const message = `
      DF 09 01 00 00 00 00 00 00 03 E9 08 90 B3 D5 1F
      30 01 00 00 08 00 DB 12 34 56 78 90 A0 00 02 00
      62 6C D9 20 00 03 E9 00 05 02 00 08 00 00 01 00
      00 FF 09 03 00 08 00 00 01 00 00 FF 05 03 00 08
      00 00 01 00 00 FF 04 01 00 08 00 00 01 00 00 FF
      02 01 00 08 00 00 01 00 00 FF 04 05 16 05 02 03
      09 0C FF FF FF FF FF FF FF FF FF 80 00 FF 09 0C
      07 DE 0C 1F FF 17 3B 0A 00 80 00 FF 09 0C 07 DF
      01 01 FF 00 00 0A 00 80 00 FF 0F 00 00 00 20
      `
      await expect(parseGbcsMessage(message, keyStore)).rejects.toThrow(
        'out of bounds'
      )
    })

    test('wrong-frame-length', async () => {
      const message = `
      DF 09 01 00 00 00 00 00 00 03 E9 08 90 B3 D5 1F
      30 01 00 00 08 00 DB 12 34 56 78 90 A0 00 02 00
      62 6E D9 20 00 03 E9 00 05 02 00 08 00 00 01 00
      00 FF 09 03 00 08 00 00 01 00 00 FF 05 03 00 08
      00 00 01 00 00 FF 04 01 00 08 00 00 01 00 00 FF
      02 01 00 08 00 00 01 00 00 FF 04 05 16 05 02 03
      09 0C FF FF FF FF FF FF FF FF FF 80 00 FF 09 0C
      07 DE 0C 1F FF 17 3B 0A 00 80 00 FF 09 0C 07 DF
      01 01 FF 00 00 0A 00 80 00 FF 0F 00 00 00 00
      `
      await expect(parseGbcsMessage(message, keyStore)).rejects.toThrow(
        'slice out of bounds'
      )
    })
  })
})
