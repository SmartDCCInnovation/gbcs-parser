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

import { verify } from 'crypto'
import {
  CipherInfo,
  Context,
  KeyStore,
  ParsedMessage,
  putBytes,
  putSeparator,
  putUnparsedBytes,
} from './context'
import { deriveKeyFromPair } from './crypto'
import {
  parseCounter,
  parseCraFlag,
  parseLength,
  parseMessageCode,
} from './common'
import { getBytes, parseBase64String, parseHexString, Slice } from './util'
import * as dlms from './dlms'
import * as gbz from './zigbee'
import * as asn1 from './asn1'

async function parseGeneralCiphering(
  ctx: Context,
  x: Slice,
): Promise<CipherInfo> {
  putSeparator(ctx, 'MAC Header')
  putBytes(ctx, 'General Ciphering', getBytes(x, 7))
  const len = parseEncodedLength(ctx, x, 'Ciphered Service Length')
  const y = getBytes(x, len)
  putBytes(ctx, 'Security Header', getBytes(y, 5))
  const cipherInfo = await parseGeneralSigning(ctx, getBytes(y, len - 5 - 12))
  putSeparator(ctx, 'MAC')
  putBytes(ctx, 'MAC', getBytes(y, 12))
  return cipherInfo
}

async function parseGeneralSigning(
  ctx: Context,
  x: Slice,
): Promise<CipherInfo> {
  putSeparator(ctx, 'Grouping Header')
  const signedDataStart = x.index + 1
  putBytes(ctx, 'General Signing', getBytes(x, 2))
  const craFlag = parseCraFlag(ctx, x, '')
  const cipherInfo: CipherInfo = {
    origCounter: x.input.buffer.subarray(x.index, x.index + 8),
    origSysTitle: x.input.buffer.subarray(x.index + 9, x.index + 17),
    recipSysTitle: x.input.buffer.subarray(x.index + 18, x.index + 26),
  }
  parseCounter(ctx, 'Originator Counter', x)
  putBytes(ctx, 'Originator System Title', getBytes(x, 9))
  putBytes(ctx, 'Recipient System Title', getBytes(x, 9))
  dlms.parseDlmsOctetString(ctx, x, 'Date Time', false)
  const otherInfoLen = parseEncodedLength(ctx, x, 'Other Information Length')
  const otherInfo = getBytes(x, otherInfoLen)
  const messageCode = parseMessageCode(ctx, ' Message Code', otherInfo)
  if (otherInfoLen >= 10) {
    cipherInfo.recipSysTitle = otherInfo.input.buffer.subarray(
      otherInfo.index,
      otherInfo.index + 8,
    )
    putBytes(ctx, ' Supplementary Remote Party ID', getBytes(otherInfo, 8))
    if (otherInfoLen >= 18) {
      parseCounter(ctx, ' Supplementary Remote Party Counter', otherInfo)
      if (otherInfoLen === 26) {
        cipherInfo.origCounter = otherInfo.input.buffer.subarray(
          otherInfo.index,
          otherInfo.index + 8,
        )
        parseCounter(ctx, ' Supplementary Originator Counter', otherInfo)
      } else if (otherInfoLen > 26) {
        asn1.parseCertificate(
          ctx,
          otherInfo,
          ' Supplementary Remote Party Key Agreement Certificate',
        )
      }
    }
  }
  const contentLen = parseEncodedLength(ctx, x, 'Content Length')
  parsePayload(ctx, getBytes(x, contentLen), messageCode, craFlag)
  const signedDataEnd = x.index
  if (x.index !== x.end) {
    putSeparator(ctx, 'Signature')
    const signatureLen = parseEncodedLength(ctx, x, 'Signature Length')
    if (signatureLen > 0) {
      const s = getBytes(x, signatureLen)
      const dataToSign = x.input.buffer.subarray(signedDataStart, signedDataEnd)
      const signature = s.input.buffer.subarray(s.index, s.end)
      putBytes(ctx, 'Signature', s)

      const pubKey = await ctx.lookupKey(cipherInfo.origSysTitle, 'DS', {})
      const valid = verify(
        'SHA256',
        dataToSign,
        { key: pubKey, dsaEncoding: 'ieee-p1363' },
        signature,
      )
      putBytes(ctx, 'Valid', getBytes(x, 0), valid ? 'true' : 'false')
    }
  }
  return cipherInfo
}

function parsePayload(
  ctx: Context,
  x: Slice,
  messageCode: number,
  craFlag: number,
) {
  putSeparator(ctx, 'Payload')
  if (messageCode === 0x0008) {
    // CS02a
    if (craFlag === 1) {
      asn1.parseProvideSecurityCredentialDetailsCommand(ctx, x)
    } else {
      asn1.parseProvideSecurityCredentialDetailsResponse(ctx, x)
    }
  } else if (messageCode >= 0x0100 && messageCode <= 0x0109) {
    // CS02b
    if (craFlag === 1) {
      asn1.parseUpdateSecurityCredentialsCommand(ctx, x)
    } else {
      asn1.parseUpdateSecurityCredentialsResponse(ctx, x)
    }
  } else if (messageCode === 0x00cb) {
    // CS02b alert
    asn1.parseUpdateSecurityCredentialsAlert(ctx, x)
  } else if (messageCode === 0x000a) {
    // CS02c
    if (craFlag === 1) {
      asn1.parseIssueSecurityCredentialsCommand(ctx, x)
    } else {
      asn1.parseIssueSecurityCredentialsResponse(ctx, x)
    }
  } else if (messageCode === 0x000b) {
    // CS02d
    if (craFlag === 1) {
      asn1.parseUpdateDeviceCertificateCommand(ctx, x)
    } else {
      asn1.parseUpdateDeviceCertificateResponse(ctx, x)
    }
  } else if (messageCode === 0x000c) {
    // CS02e
    if (craFlag === 1) {
      asn1.parseProvideDeviceCertificateCommand(ctx, x)
    } else {
      asn1.parseProvideDeviceCertificateResponse(ctx, x)
    }
  } else if (
    messageCode === 0x000d ||
    messageCode === 0x00ab ||
    messageCode === 0x000e ||
    messageCode === 0x00af
  ) {
    // CS03A1 || CS03A2 || CS03B || CS03C
    if (craFlag === 1) {
      asn1.parseJoinDeviceCommand(ctx, x)
    } else {
      asn1.parseJoindDeviceResponse(ctx, x)
    }
  } else if (messageCode === 0x000f || messageCode === 0x0010) {
    // CS04AC || CS04B
    if (craFlag === 1) {
      asn1.parseUnjoinDeviceCommand(ctx, x)
    } else {
      asn1.parseUnjoindDeviceResponse(ctx, x)
    }
  } else if (messageCode === 0x0012) {
    // CS06
    if (craFlag === 1) {
      asn1.parseActivateFirmwareCommand(ctx, x)
    } else {
      asn1.parseActivateFirmwareResponse(ctx, x)
    }
  } else if (messageCode === 0x00ca) {
    // CS06 alert
    asn1.parseActivateFirmwareAlert(ctx, x)
  } else if (messageCode === 0x0013) {
    // CS07
    if (craFlag === 1) {
      asn1.parseReadDeviceJoinDetailsCommand(ctx, x)
    } else {
      asn1.parseReadDeviceJoinDetailsResponse(ctx, x)
    }
  } else if (messageCode === 0x007f) {
    // GCS28
    if (craFlag === 1) {
      asn1.parseSetTimeCommand(ctx, x)
    } else {
      asn1.parseSetTimeResponse(ctx, x)
    }
  } else if (messageCode === 0x008b) {
    // GCS53
    gbz.parseGbzGcs53AlertPayload(ctx, x)
  } else if (messageCode === 0x008c) {
    // GCS59
    if (craFlag === 1) {
      asn1.parseGpfDeviceLogRestoreCommand(ctx, x)
    } else {
      asn1.parseGpfDeviceLogRestoreResponse(ctx, x)
    }
  } else if (messageCode === 0x00b2) {
    // GCS62
    asn1.parseGpfDeviceLogBackupAlert(ctx, x)
  } else if (messageCode === 0x00cc) {
    // Future Dated DLMS
    dlms.parseDlmsFutureDatedAlert(ctx, x)
  } else if (messageCode === 0x00cd) {
    // Future Dated GBZ
    gbz.parseGbzFutureDatedAlertPayload(ctx, x)
  } else if (messageCode === 0x00ce) {
    // FW Distribution Receipt Alert ESME
    dlms.parseDlmsFirmwareDistributionReceiptAlert(ctx, x)
  } else if (messageCode === 0x00cf) {
    // FW Distribution Receipt Alert GSME
    gbz.parseGbzFirmwareDistributionReceiptAlert(ctx, x)
  } else if (messageCode === 0x0061) {
    // ECS68
    dlms.parseDlmsBillingDataLogAlert(ctx, x)
  } else if (messageCode === 0x00d5) {
    // 8F84 Alert
    dlms.parseFailureToDeliverRemotePartyToEsme(ctx, x)
  } else if (messageCode === 0x00f0) {
    // 81A0 Alert ESME
    dlms.parseDlmsMeterIntegrityIssueWarningAlert(ctx, x)
  } else if (messageCode === 0x00f2) {
    // 81A0 Alert GSME
    gbz.parseGbzMeterIntegrityIssueWarningAlert(ctx, x)
  } else if (x.input.byte(x.index) === 1 && x.input.byte(x.index + 1) === 9) {
    if (craFlag === 3) {
      gbz.parseGbzAlertPayload(ctx, x)
    } else {
      gbz.parseGbzPayload(ctx, x)
    }
  } else if (x.input.byte(x.index) === 0xd9) {
    dlms.parseDlmsAccessRequest(ctx, x)
  } else if (x.input.byte(x.index) === 0xda) {
    dlms.parseDlmsAccessResponse(ctx, x, messageCode)
  } else if (x.input.byte(x.index) === 0x0f) {
    dlms.parseDlmsDataNotificationGbcsAlert(ctx, x)
  } else if (messageCode === 0x0128) {
    // CCS08 alert
    asn1.parseFirmwareTransferAlert(ctx, x)
  } else if (messageCode === 0x0129) {
    // CS08 Read PPMID/HCALCS Firmware Version
    if (craFlag === 3) {
      asn1.parseReadPPMIDHCALCSFirmwareVersionAlert(ctx, x)
    } else if (craFlag === 2) {
      asn1.parseReadPPMIDHCALCSFirmwareVersionResponse(ctx, x)
    } else {
      asn1.parseReadPPMIDHCALCSFirmwareVersionCommand(ctx, x)
    }
  } else {
    putBytes(ctx, 'Payload', x)
  }
  putUnparsedBytes(x)
}

function parseEncodedLength(ctx: Context, x: Slice, name: string) {
  const lenSz = parseLength(x, 0)
  putBytes(ctx, name, getBytes(x, lenSz.size), String(lenSz.length))
  return lenSz.length
}

export async function parseGbcsMessage(
  text: string,
  lookupKey: KeyStore,
): Promise<ParsedMessage> {
  const ctx: Context = {
    lookupKey,
    output: {},
    current: [],
    decryptionList: [],
  }
  let x = parseHexString(text)
  if (x.input.byte(0) !== 0xdd && x.input.byte(0) !== 0xdf) {
    // input could be base64 encoded
    const y = parseBase64String(text)
    if (y.input.byte(0) === 0xdd || y.input.byte(0) === 0xdf) {
      // assume base64 encoding if it starts with a known tag
      x = y
    }
  }
  let cipherInfo: CipherInfo
  if (x.input.byte(0) === 0xdd) {
    if (x.input.byte(1) === 0x00) {
      cipherInfo = await parseGeneralCiphering(ctx, x)
    } else {
      throw new Error('GBT not supported')
    }
  } else if (x.input.byte(0) === 0xdf) {
    cipherInfo = await parseGeneralSigning(ctx, x)
  } else {
    throw new Error('unknown frame format')
  }

  if (ctx.decryptionList.length > 0) {
    await handleDecryptGbcsData(ctx, cipherInfo, lookupKey)
  }

  return ctx.output
}

async function handleDecryptGbcsData(
  ctx: Context,
  cipherInfo: CipherInfo,
  lookupKey: KeyStore,
): Promise<void> {
  const pubKey = await lookupKey(cipherInfo.origSysTitle, 'KA', {})
  const prvKey = await lookupKey(cipherInfo.recipSysTitle, 'KA', {
    privateKey: true,
  })

  const aesKey = deriveKeyFromPair(prvKey, pubKey, cipherInfo)

  for (let i = 0; i < ctx.decryptionList.length; i++) {
    putSeparator(ctx, `Decrypted Payload ${i}`)
    ctx.decryptionList[i](cipherInfo, aesKey)
  }
}
