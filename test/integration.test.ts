import { parseGbcsMessage } from '../src/parser'

import { glob } from 'glob'
import { basename } from 'path'
import { readFile, readFileSync } from 'fs'
import { KeyStore } from '../src/context'
import { promisify } from 'util'
import { createPrivateKey, createPublicKey, KeyObject } from 'crypto'

const globP = (f: string) =>
  new Promise<string[]>((accept, reject) => {
    glob(f, (err, matches) => {
      if (err) {
        reject(err)
      }
      accept(matches)
    })
  })
const readFileP = promisify(readFile)

const keyStoreCache: {
  eui: string
  type: 'KA' | 'DS'
  privateKey: boolean
  key: KeyObject
}[] = []

const keyStore: KeyStore = async (eui, type, privateKey) => {
  if (typeof eui === 'object') {
    eui = Buffer.from(eui).toString('hex')
  }
  eui = eui.replaceAll('-', '').replaceAll(' ', '').toLowerCase()
  privateKey = privateKey ?? false

  const ce = keyStoreCache.find(
    (e) => e.eui === eui && e.type === type && e.privateKey === privateKey
  )
  if (ce) {
    return ce.key
  }

  const fileName = `${eui}-${type.toLowerCase()}.${privateKey ? 'key' : 'pem'}`
  const keyFiles = await globP(`**/${fileName}`)
  if (keyFiles.length !== 1) {
    throw new Error(`could not locate key file: ${fileName}`)
  }

  const pem = await readFileP(keyFiles[0], 'utf-8')
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
    key,
  })

  return key
}

describe('rtds', () => {
  const files = glob.sync('test/rtds/**/*HEX')
  files.forEach((file) => {
    const name = basename(file)
    test.concurrent(name, async () => {
      const message = readFileSync(file, 'utf-8')
      const output = await parseGbcsMessage(message, keyStore)
      expect('Grouping Header' in output).toBeTruthy()
      expect('Payload' in output).toBeTruthy()
    })
  })
})
