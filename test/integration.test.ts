import { parseGbcsMessage } from '../src/parser'
import { globSync } from 'glob'
import { basename } from 'path'
import { readFileSync } from 'node:fs'
import { keyStore } from './dummy-keystore'

describe('rtds', () => {
  const files = globSync('test/rtds/**/*HEX')
  files.forEach((file) => {
    const name = basename(file)
    test.concurrent(name, async () => {
      const message = readFileSync(file, 'utf-8')
      const output = await parseGbcsMessage(
        message,
        keyStore,
        '90 B3 D5 1F 30 00 00 02',
      )
      expect('Grouping Header' in output).toBeTruthy()
      expect('CRA Flag' in output['Grouping Header'].children).toBeTruthy()
      expect(
        'Other Information Length' in output['Grouping Header'].children,
      ).toBeTruthy()
      expect(
        'Message Code' in
          (output['Grouping Header']?.children['Other Information Length']
            ?.children ?? {}),
      ).toBeTruthy()
      expect('Payload' in output).toBeTruthy()
      if (file.search(/PRECOMMAND/) >= 0) {
        expect('Signature' in output).toBeFalsy()
      } else {
        expect('Signature' in output).toBeTruthy()
        if (
          'MAC' in output &&
          !String(
            output['Grouping Header']?.children?.['Other Information Length']
              ?.children?.['Message Code']?.notes,
          ).startsWith('PCS')
        ) {
          expect('MAC' in output.MAC.children).toBeTruthy()
          expect(output.MAC.children.MAC.notes).toStrictEqual('valid')
        }
      }
    })
  })
})
