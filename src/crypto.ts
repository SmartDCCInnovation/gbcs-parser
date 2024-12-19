/*
 *
 * Original copyright holders for the GBCS message parser tool:
 *
 * Copyright (c) 2019 Andre B. Oliveira
 *               2019 Enrique Giraldo
 *               2019 Cristóbal Borrero
 *
 * Copyright for subsequent changes, including porting to NodeJS,
 * updating for TypeScript and refactor to support unit testing:
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

import { assert } from 'console'
import {
  createCipheriv,
  createDecipheriv,
  createECDH,
  createHash,
  createPrivateKey,
  createPublicKey,
  createSecretKey,
  KeyObject,
  sign,
} from 'crypto'
import { CipherInfo, Context, KeyStore } from './context'
import { parseGbcsMessage } from './parser'
import { Slice, Uint8ArrayWrapper } from './util'

/**
 * standard gcm for use with GBCS - sets the cipher size and fixes the iv
 *
 * @param cipherInfo - originator/target/counter from grouping header
 * @param plainText - text to encrypt - set as empty buffer if none
 * @param aad - additional auth data - set as empty buffer if none
 * @param aesKey - output from createSecretKey
 * @param authTagLength - tag length in bytes - default is 12
 * @returns
 */
export function gcm(
  cipherInfo: CipherInfo,
  plainText: Uint8Array,
  aad: Uint8Array,
  aesKey: KeyObject,
  authTagLength?: number,
): { cipherText: Uint8Array; tag: Uint8Array } {
  const iv = new Uint8Array(12)
  iv.set(cipherInfo.origSysTitle, 0)
  iv.set([0, 0, 0, 0], 8)

  const cipher = createCipheriv('aes-128-gcm', aesKey, iv, {
    authTagLength: authTagLength ?? 12,
  })
  cipher.setAAD(aad)
  const cipherText = cipher.update(plainText)
  cipher.final()
  const tag = cipher.getAuthTag()
  return { cipherText, tag }
}

/**
 * standard gcm decrypt for use with GBCS - sets the cipher size and fixes the iv
 *
 * @param cipherInfo - originator/target/counter from grouping header
 * @param cipherText - text to decrypt - set as empty buffer if none
 * @param aad - additional auth data - set as empty buffer if none
 * @param aesKey - output from createSecretKey
 * @param tag - auth tag - default is 12
 * @returns plainText or throws error in case of auth fail
 */
export function ungcm(
  cipherInfo: CipherInfo,
  cipherText: Uint8Array,
  aad: Uint8Array,
  aesKey: KeyObject,
  tag: Uint8Array,
): Uint8Array {
  const iv = new Uint8Array(12)
  iv.set(cipherInfo.origSysTitle, 0)
  iv.set([0, 0, 0, 0], 8)

  const decipher = createDecipheriv('aes-128-gcm', aesKey, iv)
  decipher.setAAD(aad)
  decipher.setAuthTag(tag)
  const plainText = decipher.update(cipherText)
  decipher.final()
  return plainText
}

export function decryptPayloadWithKey(
  cipherInfo: CipherInfo,
  ciphertextTag: Uint8Array,
  /* Uint8Array(16) */ aesKey: KeyObject,
  doneCb: (x: Slice) => void,
) {
  const iv = new Uint8Array(12)
  iv.set(cipherInfo.origSysTitle, 0)
  iv.set([0, 0, 0, 0], 8)

  const decipher = createDecipheriv('aes-128-gcm', aesKey, iv)
  decipher.setAAD(new Uint8Array([0x31]))
  decipher.setAuthTag(ciphertextTag.subarray(-12))
  const plaintext = decipher.update(ciphertextTag.subarray(0, -12))
  decipher.final()
  const yy: Slice = {
    input: new Uint8ArrayWrapper(new Uint8Array(plaintext)),
    index: 0,
    end: plaintext.byteLength,
  }
  doneCb(yy)
}

/**
 * performs kdf as described in section 4 of GBCS
 *
 * @param privkey
 * @param pubkey
 * @param cipherInfo
 * @param mode tweaks the otherInfo field, if omitted "encryption"
 * @returns
 */
export function deriveKeyFromPair(
  privkey: string | KeyObject,
  pubkey: string | KeyObject,
  cipherInfo: CipherInfo,
  mode: 'command' | 'response' | 'alert' | 'encryption',
) {
  if (typeof privkey === 'string') {
    privkey = createPrivateKey({ key: privkey, format: 'pem' })
  }

  if (typeof pubkey === 'string') {
    pubkey = createPublicKey({ key: pubkey, format: 'pem' })
  }

  assert(privkey.asymmetricKeyType === 'ec', 'expected ec private key')
  assert(pubkey.asymmetricKeyType === 'ec', 'expected ec public key')

  const privEcKey = privkey
    .export({ type: 'sec1', format: 'der' })
    .subarray(7, 7 + 32)
  const pubEcKey = pubkey.export({ type: 'spki', format: 'der' }).subarray(-65)

  const ecdh = createECDH('prime256v1')
  ecdh.setPrivateKey(privEcKey)
  const secret = ecdh.computeSecret(pubEcKey)

  const otherInfo = new Uint8Array(33)
  otherInfo.set([0x60, 0x85, 0x74, 0x06, 0x08, 0x03, 0x00], 0) // algorithm-id
  otherInfo.set(cipherInfo.origSysTitle, 7)
  otherInfo.set([0x09], 7 + 8)
  switch (mode) {
    case 'command':
      otherInfo.set([0x01], 7 + 8 + 1)
      break
    case 'response':
      otherInfo.set([0x02], 7 + 8 + 1)
      break
    case 'alert':
      otherInfo.set([0x03], 7 + 8 + 1)
      break
    case 'encryption':
      otherInfo.set([0x04], 7 + 8 + 1)
      break
  }
  otherInfo.set(
    mode === 'encryption'
      ? (cipherInfo.supplimentryOriginatorCounter ?? cipherInfo.origCounter)
      : cipherInfo.origCounter,
    7 + 8 + 2,
  )
  otherInfo.set(
    mode === 'encryption'
      ? (cipherInfo.supplimentryRemotePartyId ?? cipherInfo.recipSysTitle)
      : cipherInfo.recipSysTitle,
    7 + 8 + 2 + 8,
  )

  const sha256 = createHash('sha256')
  sha256.update(new Uint8Array([0, 0, 0, 1]))
  sha256.update(secret)
  sha256.update(otherInfo)

  const aesKey = sha256.digest().subarray(0, 16)
  return createSecretKey(aesKey)
}

export function decryptGbcsData(
  ctx: Context,
  ciphertextAndTag: Uint8Array,
  okCallback: (x: Slice) => void,
) {
  ctx.decryptionList.push(function (cipherInfo: CipherInfo, aesKey: KeyObject) {
    decryptPayloadWithKey(cipherInfo, ciphertextAndTag, aesKey, okCallback)
  })
}

/**
 * Sign the output of transform, result is a base64 encoded string.
 *
 * @param originatorId originator id used to lookup key
 * @param payload base64 encoded gbcs message
 * @param keyStore
 * @
 */
export async function signGroupingHeader(
  originatorId: string,
  payload: string,
  keyStore: KeyStore,
): Promise<string> {
  const signersKey = await keyStore(originatorId, 'DS', { privateKey: true })
  let tbs = Buffer.from(payload, 'base64')
  if (tbs.length === 0 || tbs[0] !== 0xdf) {
    throw new Error('not general signing apdu')
  }
  /*
   * From green book. should also remove last byte as it will be replaced with
   * signature but Boxed < 1.4.1 does not currently follow specification. To
   * support this, first parse the message to determine if the signature is
   * present.
   */
  const message = await parseGbcsMessage(payload, keyStore)
  if ('Signature' in message) {
    if (message['Signature'].children['Signature Length']?.hex !== '00') {
      throw new Error('already signed')
    }
    tbs = tbs.subarray(0, -1)
  }

  const signature = sign('SHA256', tbs.subarray(1), {
    key: signersKey,
    dsaEncoding: 'ieee-p1363',
  })
  if (signature.length !== 64) {
    throw new Error('unexpected signature length')
  }
  return Buffer.concat([tbs, Buffer.from([64]), signature]).toString('base64')
}
