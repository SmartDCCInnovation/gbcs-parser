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

import {
  createPrivateKey,
  createPublicKey,
  createSecretKey,
  verify,
} from 'crypto'
import { CipherInfo } from '../src/context'
import { keyStore } from './dummy-keystore'
import * as crypto from '../src/crypto'

const device_00db1234567890a0_ka_cert = `\
-----BEGIN CERTIFICATE-----
MIIBnzCCAUagAwIBAgIQcwya2urTbTBXAi82wsid4zAKBggqhkjOPQQDAjAPMQ0w
CwYDVQQDEwRFMzU3MCAXDTE2MDQwNjAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjAA
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjyBSmF0tuTmpNxyP71istoFLNdW/
KqJfl/jRmLJt/mAa3Yk/xKHZgpH2joQptxWFI2fcDyxJAub/inNt3CnBNKOBkDCB
jTAOBgNVHQ8BAf8EBAMCAwgwEQYDVR0OBAoECEPrgzsm7h9PMDUGA1UdEQEB/wQr
MCmgJwYIKwYBBQUHCASgGzAZBg0qhjoAAYSPuQ8BAgIBBAgA2xI0VniQoDAcBgNV
HSABAf8EEjAQMA4GDCqGOgAB7e5AAQIBBDATBgNVHSMEDDAKgAhH1ArzQSkEoDAK
BggqhkjOPQQDAgNHADBEAiBaGkNFJeEibt1onn1OJBwctRIa1rogTU02g+KP1ADl
RAIgKPm8gFnJBOjUKQ5vq2vtkaf6+uq+rpD472t/rMIc4JI=
-----END CERTIFICATE-----`

const device_00db1234567890a0_ka_key = `\
-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgauGm0WGCnF/04/8kr+5taD0HC5Iy
vGQ1fRUEbUrik8OgCgYIKoZIzj0DAQehRANCAASPIFKYXS25Oak3HI/vWKy2gUs11b8qol+X+NGY
sm3+YBrdiT/EodmCkfaOhCm3FYUjZ9wPLEkC5v+Kc23cKcE0
-----END PRIVATE KEY-----`

const org_90b3d51f30000002_ka_cert = `\
-----BEGIN CERTIFICATE-----
MIIBkzCCATigAwIBAgIQN83yBrB93vhS+8YpUPIu0DAKBggqhkjOPQQDAjAaMQsw
CQYDVQQLEwIwNzELMAkGA1UEAxMCWjEwHhcNMTUxMDMwMDAwMDAwWhcNMjUxMDI5
MjM1OTU5WjAhMQswCQYDVQQLDAIwNDESMBAGA1UELQMJAJCz1R8wAAACMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEqylqI2Mw7FuLTmvCRaS3LWYP87efklmk0jnQ
LcpIZSo8La08RORiTc+165nnYACurjOW2fWI8IFgzh3Rvvv+A6NZMFcwDgYDVR0P
AQH/BAQDAgMIMBEGA1UdDgQKBAhKnOAsOauRCzAdBgNVHSABAf8EEzARMA8GDSqG
OgABhI+5DwECAQQwEwYDVR0jBAwwCoAIT1aI1+yTO+IwCgYIKoZIzj0EAwIDSQAw
RgIhAK6a4M+s7hMeTa0NyKZE6bgwD+7PTcivgnPlAlzEg+DMAiEA8rMfi8njFzrT
im85D+gu2xmyRE79EYvNqd4HDLW/SHY=
-----END CERTIFICATE-----`

const org_90b3d51f30000002_ka_key = `\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrTXI4d+DKDm2k3kI
4Mgin/l+tTSdoAe1GhB59W/B32ihRANCAASrKWojYzDsW4tOa8JFpLctZg/zt5+S
WaTSOdAtykhlKjwtrTxE5GJNz7XrmedgAK6uM5bZ9YjwgWDOHdG++/4D
-----END PRIVATE KEY-----`

const org_90b3d51f30010000_ka_cert = `\
-----BEGIN CERTIFICATE-----
MIIBkjCCATigAwIBAgIQOzYmV3Meayu+B4ZQz6FPFTAKBggqhkjOPQQDAjAaMQsw
CQYDVQQLEwIwNzELMAkGA1UEAxMCWjEwHhcNMTUxMDMwMDAwMDAwWhcNMjUxMDI5
MjM1OTU5WjAhMQswCQYDVQQLDAIwMjESMBAGA1UELQMJAJCz1R8wAQAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEknT/+KOvVtawFtOo+mDaPleVUespWBnIDrek
PzByKyJVBCheSlF2uWM027cuoM/AycbkCgrjwok3w0JY8OhAuqNZMFcwDgYDVR0P
AQH/BAQDAgMIMBEGA1UdDgQKBAhAW4xiaH2PcDAdBgNVHSABAf8EEzARMA8GDSqG
OgABhI+5DwECAQQwEwYDVR0jBAwwCoAIT1aI1+yTO+IwCgYIKoZIzj0EAwIDSAAw
RQIgFr/75lBWSxc8gzYM2B2KIo9qDgZml43a49UDQDJxy9cCIQCcncpTfMwNiHEJ
MBqualHKnx28X5I+HWDdRugWzqYbDA==
-----END CERTIFICATE-----`

const org_90b3d51f30010000_ka_key = `\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQIg5kNpbNy3E7JbH
a1dr9dQgbjv9NMv2C2JEjx+bpUShRANCAASSdP/4o69W1rAW06j6YNo+V5VR6ylY
GcgOt6Q/MHIrIlUEKF5KUXa5YzTbty6gz8DJxuQKCuPCiTfDQljw6EC6
-----END PRIVATE KEY-----`

const org_90b3d51f30010000_ds_cert = `\
-----BEGIN CERTIFICATE-----
MIIBrDCCAVKgAwIBAgIQT7xSUgGh11hsG8HEc03rnzAKBggqhkjOPQQDAjAaMQsw
CQYDVQQLEwIwNzELMAkGA1UEAxMCWjEwHhcNMTUxMDMwMDAwMDAwWhcNMjUxMDI5
MjM1OTU5WjA7MRgwFgYDVQQDDA9HSVRURVNUU1VQUExJRVIxCzAJBgNVBAsMAjAy
MRIwEAYDVQQtAwkAkLPVHzABAAAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQw
wqtaDRMXJv+9qA55KUzDdTRDKj5CRAW5ejq6D/x53OcpslF1Y8t9lYJ+TFC0jLo9
h9WJPFG5bYfDReNxf4weo1kwVzAOBgNVHQ8BAf8EBAMCB4AwEQYDVR0OBAoECESJ
l5LRlvS4MB0GA1UdIAEB/wQTMBEwDwYNKoY6AAGEj7kPAQIBBDATBgNVHSMEDDAK
gAhPVojX7JM74jAKBggqhkjOPQQDAgNIADBFAiEA39CQ51c+r1+oLhqn242f7VEY
ObV1LVXRAJHyUP3xiiICIF637Dax9BM+UVV9M7WcSe9rvRDpqksdzZKOZbPprdHF
-----END CERTIFICATE-----`

describe('deriveKeyFromPair', () => {
  test('is defined', () => {
    expect(crypto.deriveKeyFromPair).toBeDefined()
  })

  test('nominal-mac-dsp-command', () => {
    const cipherInfo: CipherInfo = {
      origCounter: Buffer.from('0000000100000000', 'hex'),
      origSysTitle: Buffer.from('90b3d51f30010000', 'hex'),
      recipSysTitle: Buffer.from('00db1234567890a0', 'hex'),
    }
    expect(
      crypto
        .deriveKeyFromPair(
          createPrivateKey(org_90b3d51f30000002_ka_key),
          createPublicKey(device_00db1234567890a0_ka_cert),
          cipherInfo,
          'command'
        )
        .export()
    ).toStrictEqual(Buffer.from('6A93E360717394015DF93E031218C9A6', 'hex'))
  })

  test('nominal-mac-device-command', () => {
    const cipherInfo: CipherInfo = {
      origCounter: Buffer.from('0000000100000000', 'hex'),
      origSysTitle: Buffer.from('90b3d51f30010000', 'hex'),
      recipSysTitle: Buffer.from('00db1234567890a0', 'hex'),
    }
    expect(
      crypto
        .deriveKeyFromPair(
          createPrivateKey(device_00db1234567890a0_ka_key),
          createPublicKey(org_90b3d51f30000002_ka_cert),
          cipherInfo,
          'command'
        )
        .export()
    ).toStrictEqual(Buffer.from('6A93E360717394015DF93E031218C9A6', 'hex'))
  })

  test('nominal-mac-remoteparty-response', () => {
    const cipherInfo: CipherInfo = {
      origCounter: Buffer.from('0000000100000000', 'hex'),
      origSysTitle: Buffer.from('00db1234567890a0', 'hex'),
      recipSysTitle: Buffer.from('90b3d51f30010000', 'hex'),
    }
    expect(
      crypto
        .deriveKeyFromPair(
          createPrivateKey(org_90b3d51f30010000_ka_key),
          createPublicKey(device_00db1234567890a0_ka_cert),
          cipherInfo,
          'response'
        )
        .export()
    ).toStrictEqual(Buffer.from('03FD30815577C49EB7E3834B63EF8302', 'hex'))
  })

  test('nominal-mac-device-response', () => {
    const cipherInfo: CipherInfo = {
      origCounter: Buffer.from('0000000100000000', 'hex'),
      origSysTitle: Buffer.from('00db1234567890a0', 'hex'),
      recipSysTitle: Buffer.from('90b3d51f30010000', 'hex'),
    }
    expect(
      crypto
        .deriveKeyFromPair(
          createPrivateKey(device_00db1234567890a0_ka_key),
          createPublicKey(org_90b3d51f30010000_ka_cert),
          cipherInfo,
          'response'
        )
        .export()
    ).toStrictEqual(Buffer.from('03FD30815577C49EB7E3834B63EF8302', 'hex'))
  })

  test('nominal-mac-remoteparty-alert', () => {
    const cipherInfo: CipherInfo = {
      origCounter: Buffer.from('00000000000007D1', 'hex'),
      origSysTitle: Buffer.from('00db1234567890a0', 'hex'),
      recipSysTitle: Buffer.from('90b3d51f30010000', 'hex'),
    }
    expect(
      crypto
        .deriveKeyFromPair(
          createPrivateKey(org_90b3d51f30010000_ka_key),
          createPublicKey(device_00db1234567890a0_ka_cert),
          cipherInfo,
          'alert'
        )
        .export()
    ).toStrictEqual(Buffer.from('558FB1FA6660AF0D9E8365C47804B8FA', 'hex'))
  })

  test('nominal-mac-device-alert', () => {
    const cipherInfo: CipherInfo = {
      origCounter: Buffer.from('00000000000007D1', 'hex'),
      origSysTitle: Buffer.from('00db1234567890a0', 'hex'),
      recipSysTitle: Buffer.from('90b3d51f30010000', 'hex'),
    }
    expect(
      crypto
        .deriveKeyFromPair(
          createPrivateKey(device_00db1234567890a0_ka_key),
          createPublicKey(org_90b3d51f30010000_ka_cert),
          cipherInfo,
          'alert'
        )
        .export()
    ).toStrictEqual(Buffer.from('558FB1FA6660AF0D9E8365C47804B8FA', 'hex'))
  })

  test('nominal-pem-keys', () => {
    const cipherInfo: CipherInfo = {
      origCounter: Buffer.from('00000000000007D1', 'hex'),
      origSysTitle: Buffer.from('00db1234567890a0', 'hex'),
      recipSysTitle: Buffer.from('90b3d51f30010000', 'hex'),
    }
    expect(
      crypto
        .deriveKeyFromPair(
          device_00db1234567890a0_ka_key,
          org_90b3d51f30010000_ka_cert,
          cipherInfo,
          'alert'
        )
        .export()
    ).toStrictEqual(Buffer.from('558FB1FA6660AF0D9E8365C47804B8FA', 'hex'))
  })
})

describe('gcm', () => {
  test('is defined', () => {
    expect(crypto.gcm).toBeDefined()
  })

  test('nominal-aad-only', () => {
    expect(
      crypto.gcm(
        {
          origCounter: Buffer.from('0102030405060708', 'hex'),
          origSysTitle: Buffer.from('90b3d51f30030000', 'hex'),
          recipSysTitle: Buffer.from('00db1234567890a1', 'hex'),
        },
        Buffer.from([]),
        Buffer.from('helloworld', 'ascii'),
        createSecretKey('000102030405060708090a0b0c0d0e0f', 'hex')
      )
    ).toStrictEqual({
      cipherText: Buffer.from([]),
      tag: Buffer.from('fb3afed43b78508864f00da3', 'hex'),
    })
  })

  test('nominal-aad-only-short', () => {
    expect(
      crypto.gcm(
        {
          origCounter: Buffer.from('0102030405060708', 'hex'),
          origSysTitle: Buffer.from('90b3d51f30030000', 'hex'),
          recipSysTitle: Buffer.from('00db1234567890a1', 'hex'),
        },
        Buffer.from([]),
        Buffer.from('helloworld', 'ascii'),
        createSecretKey('000102030405060708090a0b0c0d0e0f', 'hex'),
        4
      )
    ).toStrictEqual({
      cipherText: Buffer.from([]),
      tag: Buffer.from('fb3afed4', 'hex'),
    })
  })

  test('nominal', () => {
    expect(
      crypto.gcm(
        {
          origCounter: Buffer.from('0102030405060708', 'hex'),
          origSysTitle: Buffer.from('90b3d51f30030000', 'hex'),
          recipSysTitle: Buffer.from('00db1234567890a1', 'hex'),
        },
        Buffer.from('one two three', 'ascii'),
        Buffer.from('helloworld', 'ascii'),
        createSecretKey('000102030405060708090a0b0c0d0e0f', 'hex')
      )
    ).toStrictEqual({
      cipherText: Buffer.from('584fa806b24491178829d46c38', 'hex'),
      tag: Buffer.from('6b33bdcb1e223242ec20b957', 'hex'),
    })
  })
})

describe('signGroupingHeader', () => {
  test('is defined', () => {
    expect(crypto.signGroupingHeader).toBeDefined()
  })

  test('empty', () => {
    const message = Buffer.from('')
    return expect(
      crypto.signGroupingHeader(
        '90B3D51F30010000',
        message.toString('base64'),
        keyStore
      )
    ).rejects.toThrow()
  })

  test('bad-payload', () => {
    const message = Buffer.from('hello world')
    return expect(
      crypto.signGroupingHeader(
        '90B3D51F30010000',
        message.toString('base64'),
        keyStore
      )
    ).rejects.toThrow()
  })

  test('nominal/missing-signature', async () => {
    const message = Buffer.from(
      `
      DF 09 01 00 00 00 00 00 00 03 E9 08 90 B3 D5 1F
      30 01 00 00 08 00 DB 12 34 56 78 90 A0 00 02 00
      62 6C D9 20 00 03 E9 00 05 02 00 08 00 00 01 00
      00 FF 09 03 00 08 00 00 01 00 00 FF 05 03 00 08
      00 00 01 00 00 FF 04 01 00 08 00 00 01 00 00 FF
      02 01 00 08 00 00 01 00 00 FF 04 05 16 05 02 03
      09 0C FF FF FF FF FF FF FF FF FF 80 00 FF 09 0C
      07 DE 0C 1F FF 17 3B 0A 00 80 00 FF 09 0C 07 DF
      01 01 FF 00 00 0A 00 80 00 FF 0F 00 00 00`.replace(/[ \n\t]/g, ''),
      'hex'
    )
    const signed = await crypto.signGroupingHeader(
      '90B3D51F30010000',
      message.toString('base64'),
      keyStore
    )
    const signedBuffer = Buffer.from(signed, 'base64')
    expect(signedBuffer.length).toBe(message.length + 1 + 64)
    const signature = signedBuffer.subarray(-64)
    expect(signature.length).toBe(64)

    expect(
      verify(
        'SHA256',
        message.subarray(1),
        {
          key: createPublicKey(org_90b3d51f30010000_ds_cert),
          dsaEncoding: 'ieee-p1363',
        },
        signature
      )
    ).toBeTruthy()
  })

  test('nominal/null-signature', async () => {
    const message = Buffer.from(
      `
      DF 09 01 00 00 00 00 00 00 03 E9 08 90 B3 D5 1F
      30 01 00 00 08 00 DB 12 34 56 78 90 A0 00 02 00
      62 6C D9 20 00 03 E9 00 05 02 00 08 00 00 01 00
      00 FF 09 03 00 08 00 00 01 00 00 FF 05 03 00 08
      00 00 01 00 00 FF 04 01 00 08 00 00 01 00 00 FF
      02 01 00 08 00 00 01 00 00 FF 04 05 16 05 02 03
      09 0C FF FF FF FF FF FF FF FF FF 80 00 FF 09 0C
      07 DE 0C 1F FF 17 3B 0A 00 80 00 FF 09 0C 07 DF
      01 01 FF 00 00 0A 00 80 00 FF 0F 00 00 00 00`.replace(/[ \n\t]/g, ''),
      'hex'
    )
    const signed = await crypto.signGroupingHeader(
      '90B3D51F30010000',
      message.toString('base64'),
      keyStore
    )
    const signedBuffer = Buffer.from(signed, 'base64')
    expect(signedBuffer.length).toBe(message.length + 64)
    const signature = signedBuffer.subarray(-64)
    expect(signature.length).toBe(64)

    expect(
      verify(
        'SHA256',
        message.subarray(1, -1),
        {
          key: createPublicKey(org_90b3d51f30010000_ds_cert),
          dsaEncoding: 'ieee-p1363',
        },
        signature
      )
    ).toBeTruthy()
  })

  test('already-signed', async () => {
    const message = Buffer.from(
      `
      df 09 01 00 00 00 00 00 00 03 e8 08 90 b3 d5 1f
      30 01 00 00 08 00 db 12 34 56 78 90 a0 00 02 00
      0c 06 30 04 03 02 07 80 40 26 b0 ae 08 84 a5 aa
      5d 21 76 eb b5 68 58 db f2 57 c6 68 5b 4d 3c bc
      96 0c 02 5b 1a 90 1f 8f 21 7d d7 eb 02 0b cf 50
      62 0c 3a 9c 51 bd 3f a5 0b ae 67 ec df 34 3d 3e
      02 73 1d 9c c9 b2 41 c2 b2`.replace(/[ \n\t]/g, ''),
      'hex'
    )
    await expect(
      crypto.signGroupingHeader(
        '90B3D51F30010000',
        message.toString('base64'),
        keyStore
      )
    ).rejects.toThrow('already signed')
  })
})
