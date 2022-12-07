import { parseGbcsMessage } from '../src/parser'
import { glob } from 'glob'
import { basename } from 'path'
import { readFileSync } from 'node:fs'
import { keyStore } from './dummy-keystore'

describe('rtds', () => {
  const files = glob.sync('test/rtds/**/*HEX')
  files.forEach((file) => {
    const name = basename(file)
    test.concurrent(name, async () => {
      const message = readFileSync(file, 'utf-8')
      const output = await parseGbcsMessage(message, keyStore)
      expect('Grouping Header' in output).toBeTruthy()
      expect('Payload' in output).toBeTruthy()
      if (file.search(/PRECOMMAND/) >= 0) {
        expect('Signature' in output).toBeFalsy()
      } else {
        expect('Signature' in output).toBeTruthy()
      }
    })
  })
})
