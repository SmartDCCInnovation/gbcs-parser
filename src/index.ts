/*
 * Created on Mon Jul 11 2022
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

import { createPrivateKey, createPublicKey, KeyObject } from 'crypto'
import { parseGbcsMessage } from './parser'

const X = 1
export default X

const internalKeyStore: Record<
  string,
  | Record<
      'KA' | 'DS',
      Record<'public' | 'private', string | undefined> | undefined
    >
  | undefined
> = {
  '000781d7000036ce': {
    KA: {
      public: `-----BEGIN CERTIFICATE-----
      MIIBnzCCAUSgAwIBAgIQHweCMqI78XpsnJii0mjNpjAKBggqhkjOPQQDAjAhMQsw
      CQYDVQQLDAIwNDESMBAGA1UELQMJAJCz1R8wAAACMCAXDTIyMDYxNjEyNTAxN1oY
      Dzk5OTkxMjMxMjM1OTU5WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEu+io
      fr9EVpI+o0XnJwR5+MnHOIdTtFcrQxkrUAnhvzg0yP8qtcPDI/vjPjfTL+UvtlWg
      EeuKyM5qXFlQPyxFmaN9MHswDgYDVR0PAQH/BAQDAgMIMDUGA1UdEQEB/wQrMCmg
      JwYIKwYBBQUHCASgGzAZBg0qhjoAAYKE8lMBgVUCBAgAB4HXAAA2zjAdBgNVHSAB
      Af8EEzARMA8GDSqGOgABhI+5DwECAQQwEwYDVR0jBAwwCoAIQmk1NdPd4QEwCgYI
      KoZIzj0EAwIDSQAwRgIhAO0kio5pcTJu7e9PKjYAhJ0kMniAcHiJQlmDpuVewRID
      AiEA7ClqOiDpE2mseGUwGzdNYmnpBNEacWVen4qKC+pvyzw=
      -----END CERTIFICATE-----`,
      private: undefined,
    },
    DS: undefined,
  },
  '90b3d51f30010000': {
    KA: {
      private: `-----BEGIN PRIVATE KEY-----
      MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQIg5kNpbNy3E7JbH
      a1dr9dQgbjv9NMv2C2JEjx+bpUShRANCAASSdP/4o69W1rAW06j6YNo+V5VR6ylY
      GcgOt6Q/MHIrIlUEKF5KUXa5YzTbty6gz8DJxuQKCuPCiTfDQljw6EC6
      -----END PRIVATE KEY-----`,
      public: undefined,
    },
    DS: undefined,
  },
}

async function keyStore(
  eui: string | Uint8Array,
  type: 'KA' | 'DS',
  privateKey?: boolean
): Promise<KeyObject> {
  if (typeof eui === 'object') {
    eui = Buffer.from(eui).toString('hex')
  }
  eui = eui.replaceAll('-', '').replaceAll(' ', '').toLowerCase()
  const entity = internalKeyStore[eui]
  if (entity === undefined) {
    throw new Error(`eui ${eui} not in key store`)
  }
  const kads = entity[type]
  if (kads === undefined) {
    throw new Error(`eui ${eui} does not have ${type} in keystore`)
  }
  let pem = kads[privateKey ? 'private' : 'public']
  if (pem === undefined) {
    throw new Error(
      `eui ${eui} does not have ${
        privateKey ? 'private' : 'public'
      } ${type} in keystore`
    )
  }
  pem = pem.replaceAll(/  +/g, '')
  if (privateKey) {
    return createPrivateKey(pem)
  }
  return createPublicKey(pem)
}

parseGbcsMessage(
  '3QAAAAAAAIGuEQAAAADfCQIAAAGBhrzUOAgAB4HXAAA2zgiQs9UfMAEAAAwH5gYVAg4yDgAAAAACACdu2iC81DgAAAECAgEBAgIWAgIFCQkEAAABgYa81DgJCAAHgdcAADbOCQiQs9UfMAEAAAkAAgIWAgICCQECCQAJKzEAAAAAQHHSN6oaMTeYvoFhhf9HeMAEqhAXOkxjsDD56klGzMMASiR66uIBAwAAbyNBmeihFoQnziuZ',
  keyStore
)
  .then((x) => console.log(JSON.stringify(x, null, 2)))
  .catch(console.error)
