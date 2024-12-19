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
        'out of bounds',
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
        'slice out of bounds',
      )
    })
  })

  describe('real-payloads', () => {
    test('double-long', async () => {
      const message =
        '3QAAAAAAAEQRAAAAAN8JAgAAAYw0vVLYCBzBG7EAAB0CCJCz1R8wAQAAAAIAaRDaIL1S2AAAAQX+evxTAQEAAEGfoFG78UF8nO+4bw=='
      const output = await parseGbcsMessage(
        message,
        keyStore,
        '90 B3 D5 1F 30 00 00 02',
      )
      expect('MAC Header' in output).toBeTruthy()
      expect('Grouping Header' in output).toBeTruthy()
      expect('CRA Flag' in output['Grouping Header'].children).toBeTruthy()
      expect('Payload' in output).toBeTruthy()
      expect('Signature' in output).toBeTruthy()
      expect('MAC' in output).toBeTruthy()
      expect('DLMS Access Response' in output.Payload.children).toBeTruthy()
      expect(
        output.Payload.children['DLMS Access Response'].children?.[
          'List of Access Response Data'
        ],
      ).toBeTruthy()
      expect(
        output.Payload.children?.['DLMS Access Response'].children?.[
          'List of Access Response Data'
        ].children?.['[0] Double Long'],
      ).toBeTruthy()
      expect(
        output.Payload.children?.['DLMS Access Response'].children?.[
          'List of Access Response Data'
        ].children?.['[0] Double Long'].hex,
      ).toBe('05 FE 7A FC 53')
      expect(
        output.Payload.children?.['DLMS Access Response'].children?.[
          'List of Access Response Data'
        ].children?.['[0] Double Long'].notes,
      ).toBe('-25494445')
      expect('MAC' in output.MAC.children).toBeTruthy()
      expect(output.MAC.children.MAC.hex).toBe(
        '41 9F A0 51 BB F1 41 7C 9C EF B8 6F',
      )
      expect(output.MAC.children.MAC.notes).toBe('unknown')
    })

    describe('cs02a', () => {
      test('cell-usage-implicit', async () => {
        const message =
          '3QAAAAAAAIHHEQAAAADfCQIAAAGNHkxZdAiIc4T/AC+WHgiQs9UfMAAAAgACAAiBkjCBjzAlAgEACgEAAgEAMBowGAMCAgQECAAAAAAAAAAABAhKm97xVx77EzA/AgECCgEAAgEAMDQwGAMCB4AECJCz1R8wAQAABAhEiZeS0Zb0uDAYAwIDCAQIkLPVHzABAAAECEBbjGJofY9wMCUCAQUKAQACAQAwGjAYAwIHgAQIkLPVHzAAAAQECEs460dWHZPoAD1DusMm0XNJ8jJgLQ=='
        const output = await parseGbcsMessage(message, keyStore)
        expect('MAC Header' in output).toBeTruthy()
        expect('Grouping Header' in output).toBeTruthy()
        expect('Payload' in output).toBeTruthy()
        expect('Signature' in output).toBeTruthy()
        expect(
          'Provide Security Credential Details Response' in
            output.Payload.children,
        ).toBeTruthy()
        expect(
          output.Payload.children?.[
            'Provide Security Credential Details Response'
          ].children?.['[0] Remote Party Details']?.children,
        ).toMatchObject({
          'Remote Party Role': { hex: '02 01 00', notes: 'Root' },
          'Status Code': { hex: '0A 01 00', notes: 'Success' },
          'Current Seq Number': { hex: '02 01 00', notes: '0' },
          'Trust Anchor Cell Details': {
            children: {
              '[0] Trust Anchor Cell Contents': {
                children: {
                  'Key Usage': { hex: '03 02 02 04', notes: 'Key Cert Sign' },
                  'Cell Usage': {
                    hex: '',
                    notes: 'Management (DEFAULT)',
                  },
                  'Subject Unique ID': { hex: '04 08 00 00 00 00 00 00 00 00' },
                  'Subject Key Identifier': {
                    hex: '04 08 4A 9B DE F1 57 1E FB 13',
                  },
                },
              },
            },
          },
        })
      })

      test('cell-usage-explicit', async () => {
        const message =
          '3QAAAAAAAIHYEQAAAADfCQIAAAGNHhsLFggAC2v/HjABIgiQs9UfMAAAAgACAAiBozCBoDAoAgEACgEAAgEAMB0wGwMCAgQCAQAECAAAAAAAAAAABAhIzxsyaXxGaTBFAgECCgEAAgEAMDowGwMCAwgCAQAECJCz1R8wAQAABAhAW4xiaH2PcDAbAwIHgAIBAAQIkLPVHzABAAAECESJl5LRlvS4MC0CAQUKAQACBgGNEsX1TjAdMBsDAgeAAgEABAiQs9UfMAAABAQISzjrR1Ydk+gAbb0Lu/KdLnwXjZOh'
        const output = await parseGbcsMessage(message, keyStore)
        expect('MAC Header' in output).toBeTruthy()
        expect('Grouping Header' in output).toBeTruthy()
        expect('Payload' in output).toBeTruthy()
        expect('Signature' in output).toBeTruthy()
        expect(
          'Provide Security Credential Details Response' in
            output.Payload.children,
        ).toBeTruthy()
        expect(
          output.Payload.children?.[
            'Provide Security Credential Details Response'
          ].children?.['[0] Remote Party Details']?.children,
        ).toMatchObject({
          'Remote Party Role': { hex: '02 01 00', notes: 'Root' },
          'Status Code': { hex: '0A 01 00', notes: 'Success' },
          'Current Seq Number': { hex: '02 01 00', notes: '0' },
          'Trust Anchor Cell Details': {
            children: {
              '[0] Trust Anchor Cell Contents': {
                children: {
                  'Key Usage': { hex: '03 02 02 04', notes: 'Key Cert Sign' },
                  'Cell Usage': {
                    hex: '02 01 00',
                    notes: 'Management',
                  },
                  'Subject Unique ID': { hex: '04 08 00 00 00 00 00 00 00 00' },
                  'Subject Key Identifier': {
                    hex: '04 08 48 CF 1B 32 69 7C 46 69',
                  },
                },
              },
            },
          },
        })
      })
    })
  })

  describe('mac-validation', () => {
    describe('gbcs-sme.c.nc', () => {
      test('command', async () => {
        const message = `
        DD:00:00:00:00:00:00:54:11:00:00:00:00:DF:09:01:
        00:00:00:00:00:00:00:02:08:12:34:56:78:9A:BC:DE:
        F0:08:FF:FF:FF:FF:FF:FF:FF:FE:00:02:00:22:20:D9:
        20:00:00:02:00:01:02:00:01:00:00:5E:2C:03:02:02:
        01:09:0C:07:DF:01:05:FF:00:00:00:00:80:00:FF:00:
        0F:1D:D0:0D:67:45:EB:D8:E0:A6:63:A4
        `

        const output = await parseGbcsMessage(
          message,
          keyStore,
          'abababababababab',
        )
        expect('Grouping Header' in output).toBeTruthy()
        expect('Payload' in output).toBeTruthy()
        expect('Signature' in output).toBeTruthy()
        expect(output['Signature'].children['Signature Length'].hex).toBe('00')
        expect('MAC' in output).toBeTruthy()
        expect('MAC' in output.MAC.children).toBeTruthy()
        expect(output.MAC.children.MAC.hex).toBe(
          '0F 1D D0 0D 67 45 EB D8 E0 A6 63 A4',
        )
        expect(output.MAC.children.MAC.notes).toBe('valid')
      })

      test('response', async () => {
        const message = `
        DD:00:00:00:00:00:00:40:11:00:00:00:00:DF:09:02:
        00:00:00:00:00:00:00:02:08:FF:FF:FF:FF:FF:FF:FF:
        FE:08:12:34:56:78:9A:BC:DE:F0:00:02:00:22:0C:DA:
        20:00:00:02:00:00:01:00:01:02:00:00:0B:3C:1B:31:
        2C:EA:E9:C1:30:06:0E:29
        `

        const output = await parseGbcsMessage(
          message,
          keyStore,
          'abababababababab',
        )
        expect('Grouping Header' in output).toBeTruthy()
        expect('Payload' in output).toBeTruthy()
        expect('Signature' in output).toBeTruthy()
        expect(output['Signature'].children['Signature Length'].hex).toBe('00')
        expect('MAC' in output).toBeTruthy()
        expect('MAC' in output.MAC.children).toBeTruthy()
        expect(output.MAC.children.MAC.hex).toBe(
          '0B 3C 1B 31 2C EA E9 C1 30 06 0E 29',
        )
        expect(output.MAC.children.MAC.notes).toBe('valid')
      })
    })

    test('gfi-ecs01a', async () => {
      const message = `
      DD 00 00 00 00 00 00 82 04 F4 11 00 00 00 00 DF 09 01 00 00 00 00 00 00 03 E8 08 90 B3 D5 1F 30
      01 00 00 08 00 DB 12 34 56 78 90 A0 00 02 00 19 82 04 7E D9 20 00 03 E8 00 15 02 00 14 00 00 0D
      00 00 FF 07 02 00 14 00 00 0D 00 00 FF 08 02 00 14 00 00 0D 00 00 FF 09 02 00 0B 00 01 0B 00 00
      FF 02 02 00 15 00 00 10 01 0B FF 02 02 00 15 00 00 10 01 0C FF 02 02 00 15 00 00 10 01 0D FF 02
      02 00 15 00 00 10 01 0E FF 02 02 00 15 00 00 10 01 0F FF 02 02 00 15 00 00 10 01 10 FF 02 02 00
      15 00 00 10 01 11 FF 02 02 00 15 00 00 10 01 12 FF 02 02 23 28 00 00 5E 2C 02 00 04 02 00 71 00
      00 13 14 04 FF 06 02 00 71 00 00 13 14 00 FF 06 02 00 14 00 00 0D 00 00 FF 0A 02 23 28 00 00 5E
      2C 80 1D 06 02 23 28 00 00 5E 2C 02 00 06 02 00 71 00 00 13 14 04 FF 07 02 00 71 00 00 13 14 00
      FF 07 02 23 28 00 00 3F 01 01 FF 06 15 01 01 02 03 09 06 73 70 72 69 6E 67 09 0C 07 DF 01 0F FF
      00 00 00 00 80 00 FF 09 01 01 01 01 02 08 09 01 01 11 01 11 01 11 01 11 01 11 01 11 01 11 01 01
      01 02 02 11 01 01 01 02 03 09 04 03 0B 2B 00 09 06 00 00 0A 00 64 FF 12 00 01 01 01 02 03 12 00
      01 09 05 07 DF 01 1E FF 11 01 01 01 06 FF FF FF FF 01 01 06 FF FF FF FF 01 01 06 FF FF FF FF 01
      01 06 FF FF FF FF 01 01 06 FF FF FF FF 01 01 06 FF FF FF FF 01 01 06 FF FF FF FF 01 01 06 FF FF
      FF FF 03 00 02 03 02 02 0F 00 0F FC 02 03 12 00 00 09 06 00 00 00 00 00 00 0F 00 01 01 02 02 09
      00 10 03 E8 02 03 02 02 0F 03 0F FC 02 03 12 00 03 09 06 01 00 01 08 00 FF 0F 02 01 50 02 02 09
      01 01 10 39 AF 02 02 09 01 02 10 00 00 02 02 09 01 03 10 00 00 02 02 09 01 04 10 00 00 02 02 09
      01 05 10 00 00 02 02 09 01 06 10 00 00 02 02 09 01 07 10 00 00 02 02 09 01 08 10 00 00 02 02 09
      01 09 10 00 00 02 02 09 01 0A 10 00 00 02 02 09 01 0B 10 00 00 02 02 09 01 0C 10 00 00 02 02 09
      01 0D 10 00 00 02 02 09 01 0E 10 00 00 02 02 09 01 0F 10 00 00 02 02 09 01 10 10 00 00 02 02 09
      01 11 10 00 00 02 02 09 01 12 10 00 00 02 02 09 01 13 10 00 00 02 02 09 01 14 10 00 00 02 02 09
      01 15 10 00 00 02 02 09 01 16 10 00 00 02 02 09 01 17 10 00 00 02 02 09 01 18 10 00 00 02 02 09
      01 19 10 00 00 02 02 09 01 1A 10 00 00 02 02 09 01 1B 10 00 00 02 02 09 01 1C 10 00 00 02 02 09
      01 1D 10 00 00 02 02 09 01 1E 10 00 00 02 02 09 01 1F 10 00 00 02 02 09 01 20 10 00 00 02 02 09
      01 21 10 00 00 02 02 09 01 22 10 00 00 02 02 09 01 23 10 00 00 02 02 09 01 24 10 00 00 02 02 09
      01 25 10 00 00 02 02 09 01 26 10 00 00 02 02 09 01 27 10 00 00 02 02 09 01 28 10 00 00 02 02 09
      01 29 10 00 00 02 02 09 01 2A 10 00 00 02 02 09 01 2B 10 00 00 02 02 09 01 2C 10 00 00 02 02 09
      01 2D 10 00 00 02 02 09 01 2E 10 00 00 02 02 09 01 2F 10 00 00 02 02 09 01 30 10 00 00 02 02 09
      01 A1 10 00 00 02 02 09 01 A2 10 00 00 02 02 09 01 A3 10 00 00 02 02 09 01 A4 10 00 00 02 02 09
      01 A5 10 00 00 02 02 09 01 A6 10 00 00 02 02 09 01 A7 10 00 00 02 02 09 01 A8 10 00 00 02 02 09
      01 B1 10 00 00 02 02 09 01 B2 10 00 00 02 02 09 01 B3 10 00 00 02 02 09 01 B4 10 00 00 02 02 09
      01 B5 10 00 00 02 02 09 01 B6 10 00 00 02 02 09 01 B7 10 00 00 02 02 09 01 B8 10 00 00 02 02 09
      01 C1 10 00 00 02 02 09 01 C2 10 00 00 02 02 09 01 C3 10 00 00 02 02 09 01 C4 10 00 00 02 02 09
      01 C5 10 00 00 02 02 09 01 C6 10 00 00 02 02 09 01 C7 10 00 00 02 02 09 01 C8 10 00 00 02 02 09
      01 D1 10 00 00 02 02 09 01 D2 10 00 00 02 02 09 01 D3 10 00 00 02 02 09 01 D4 10 00 00 02 02 09
      01 D5 10 00 00 02 02 09 01 D6 10 00 00 02 02 09 01 D7 10 00 00 02 02 09 01 D8 10 00 00 09 0C 00
      00 00 00 00 00 00 00 00 80 00 FF 09 0C 00 00 00 00 00 00 00 00 00 80 00 FF 09 0C 00 00 00 00 00
      00 00 00 00 80 00 FF 09 0C 00 00 00 00 00 00 00 00 00 80 00 FF 09 0C 00 00 00 00 00 00 00 00 00
      80 00 FF 09 0C 00 00 00 00 00 00 00 00 00 80 00 FF 40 87 6C 14 FE 27 B4 51 FB 48 9D 84 75 D3 52
      5D DC DA AE 46 B6 5A B7 04 3A BB 1C 7D 82 0A C4 F4 66 3F 35 E8 4A 9C 1E 66 E6 73 73 49 36 B1 91
      94 65 78 6D E7 F3 AC 17 F9 6B C3 06 00 36 9E 96 34 87 40 74 C0 81 51 C6 16 1E 0E 20 31 99
      `
      const output = await parseGbcsMessage(
        message,
        keyStore,
        '90 B3 D5 1F 30 00 00 02',
      )
      expect('Grouping Header' in output).toBeTruthy()
      expect('Payload' in output).toBeTruthy()
      expect('Signature' in output).toBeTruthy()
      expect(output['Signature'].children['Signature Length'].hex).toBe('40')
      expect('MAC' in output).toBeTruthy()
      expect('MAC' in output.MAC.children).toBeTruthy()
      expect(output.MAC.children.MAC.hex).toBe(
        '40 74 C0 81 51 C6 16 1E 0E 20 31 99',
      )
      expect(output.MAC.children.MAC.notes).toBe('valid')
    })
  })
})
