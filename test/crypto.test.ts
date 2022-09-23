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

import { createPrivateKey, createPublicKey, createSecretKey } from 'crypto'
import { CipherInfo } from '../src/context'
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
