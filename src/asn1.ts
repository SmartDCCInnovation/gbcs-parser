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

// ASN.1 DER Payloads

import { parseLength, parseNumber } from './common'
import { Context, putBytes } from './context'
import { getAlertCodeName, getBytes, getDecimalString, Slice } from './util'

// CS02a Provide Security Credentials

export function parseProvideSecurityCredentialDetailsCommand(
  ctx: Context,
  x: Slice
) {
  const s = parseSequence(ctx, x, 'Provide Security Credential Details Command')
  const indent = ' '
  parseTrustAnchorCellIdentifier(
    ctx,
    s,
    `${indent}Authorising Remote Party TA Cell Identifier`
  )
  parseSequenceOf(
    ctx,
    s,
    `${indent}Remote Party Roles Credentials Required`,
    parseRemotePartyRole
  )
}

export function parseProvideSecurityCredentialDetailsResponse(
  ctx: Context,
  x: Slice
) {
  parseSequenceOf(
    ctx,
    x,
    'Provide Security Credential Details Response',
    (ctx, x, name) => {
      parseSequenceOf(ctx, x, `${name}Remote Party Details`, (ctx, x, name) => {
        const indent = name.match(/^ */)?.[0] ?? ''
        parseRemotePartyRole(ctx, x, indent)
        parseStatusCode(ctx, x, indent)
        if (x.index < x.end) {
          parseSeqNumber(ctx, x, `${indent}Current Seq Number`)
          parseSequenceOf(
            ctx,
            x,
            `${indent}Trust Anchor Cell Details`,
            (ctx, x, name) => {
              const indent = (name.match(/^ */)?.[0] ?? '') + ' '
              const s = parseSequence(
                ctx,
                x,
                `${name}Trust Anchor Cell Contents`
              )
              parseKeyUsage(ctx, s, indent)
              parseCellUsage(ctx, s, indent)
              parseDerOctetString(ctx, s, `${indent}Subject Unique ID`)
              parseDerOctetString(ctx, s, `${indent}Subject Key Identifier`)
            }
          )
        }
      })
    }
  )
}

// CS02b Update Security Credentials

export function parseUpdateSecurityCredentialsCommand(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Update Security Credentials Command')
  const indent = ' '
  parseAuthorisingRemotePartyControl(ctx, s, indent)
  parseSequenceOf(ctx, s, `${indent}Replacements`, parseTrustAnchorReplacement)
  parseSequenceOf(
    ctx,
    s,
    `${indent}Certification Path Certificates`,
    parseCertificate
  )
  if (isPresent(s, 0x18))
    parseGeneralizedTime(ctx, s, `${indent}Execution Date Time`)
}

export function parseUpdateSecurityCredentialsResponse(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Update Security Credentials Response')
  const indent = ' '
  parseNull(ctx, s, `${indent}Command Accepted`)
  if (isPresent(s, 0x30))
    parseUpdateSecurityCredentialsExecutionOutcome(ctx, s, indent)
}

export function parseUpdateSecurityCredentialsAlert(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Update Security Credentials Alert')
  const indent = ' '
  parseAsn1AlertCode(ctx, s, indent)
  parseGeneralizedTime(ctx, s, `${indent}Execution Date Time`)
  parseUpdateSecurityCredentialsExecutionOutcome(ctx, s, indent)
}

export function parseUpdateSecurityCredentialsExecutionOutcome(
  ctx: Context,
  x: Slice,
  indent: string
) {
  const s = parseSequence(ctx, x, `${indent}Execution Outcome`)
  indent = indent + ' '
  parseSeqNumber(ctx, s, `${indent}Authorising Remote Party Seq Number`)
  parseCredentialsReplacementMode(ctx, s, indent)
  parseSequenceOf(
    ctx,
    s,
    `${indent}Remote Party Seq Number Changes`,
    parseRemotePartySeqNumberChange
  )
  parseSequenceOf(
    ctx,
    s,
    `${indent}Replacement Outcomes`,
    parseReplacementOutcome
  )
}

export function parseReplacementOutcome(ctx: Context, x: Slice, name: string) {
  const s = parseSequence(ctx, x, `${name}Replacement Outcome`)
  const indent = (name.match(/^ */)?.[0] ?? '') + ' '
  parseTrustAnchorCellIdentifier(ctx, s, `${indent}Affected Trust Anchor Cell`)
  parseStatusCode(ctx, s, indent)
  parseDerOctetString(ctx, s, `${indent}Existing Subject Unique ID`)
  parseDerOctetString(ctx, s, `${indent}Existing Subject Key ID`)
  parseDerOctetString(ctx, s, `${indent}Replacing Subject Unique ID`)
  parseDerOctetString(ctx, s, `${indent}Replacing Subject Key ID`)
}

// CS02c Issue Security Credentials

export function parseIssueSecurityCredentialsCommand(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Issue Security Credentials Command')
  parseKeyUsage(ctx, s, ' ')
}

export function parseIssueSecurityCredentialsResponse(ctx: Context, x: Slice) {
  if (isPresent(x, 0x30)) {
    putBytes(ctx, 'Certification Request', x)
  } else {
    parseInteger(ctx, x, 'Response Code', {
      1: 'Invalid Key Usage',
      2: 'Key Pair Generation Failed',
      3: 'CR Production Failed',
    })
  }
}

// CS02d Update Device Certificate on Device

export function parseUpdateDeviceCertificateCommand(ctx: Context, x: Slice) {
  parseCertificate(ctx, x)
}

export function parseUpdateDeviceCertificateResponse(ctx: Context, x: Slice) {
  const responseCodes = {
    0: 'Success',
    1: 'Invalid Certificate',
    2: 'Wrong Device Identity',
    3: 'Invalid Key Usage',
    4: 'No Corresponding Key Pair Generated',
    5: 'Wrong Public Key',
    6: 'Certificate Storage Failed',
    7: 'Private Key Change Failed',
  }
  parseInteger(ctx, x, 'Response Code', responseCodes)
}

// CS02e Provide Device Certificate from Device

export function parseProvideDeviceCertificateCommand(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Provide Device Certificate Command')
  parseKeyUsage(ctx, s, ' ')
}

export function parseProvideDeviceCertificateResponse(ctx: Context, x: Slice) {
  if (isPresent(x, 0x30)) {
    parseCertificate(ctx, x)
  } else {
    parseInteger(ctx, x, 'Response Code', {
      1: 'Invalid Key Usage',
      2: 'No Certificate Held',
      3: 'Certificate Retrieval Failure',
    })
  }
}

// CS03XY

export function parseJoinDeviceCommand(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Join Device Command')
  const indent = ' '
  parseInteger(ctx, s, `${indent}Join Method and Role`, {
    0: 'Method A Initiator',
    1: 'Method A Responder',
    2: 'Method B',
    3: 'Method C',
  })
  parseDerOctetString(ctx, s, `${indent}Entity Id`)
  parseDeviceType(ctx, s, indent)
  if (s.index < s.end) {
    parseCertificate(ctx, s, indent)
  }
}

export function parseJoindDeviceResponse(ctx: Context, x: Slice) {
  const responseCodes = {
    0: 'Success',
    1: 'Invalid Message Code for Join Method and Role',
    2: 'Invalid Join Method and Role',
    3: 'Incompatible with Existing Entry',
    4: 'Device Log Full',
    5: 'Write Failure',
    6: 'Key Agreement no Resources',
    7: 'Key Agreement Unknown Issuer',
    8: 'Key Agreement Unsupported Suite',
    9: 'Key Agreement Bad Message',
    10: 'Key Agreement Bad Key Confirm',
    11: 'Invalid or Missing Certificate',
    12: 'No Partner Link Key Received',
    13: 'No CBKE Response',
  }
  parseInteger(ctx, x, 'Response Code', responseCodes)
}

// CS04XY

export function parseUnjoinDeviceCommand(ctx: Context, x: Slice) {
  parseDerOctetString(ctx, x, 'Entity Id')
}

export function parseUnjoindDeviceResponse(ctx: Context, x: Slice) {
  parseInteger(ctx, x, 'Response Code', {
    0: 'Success',
    1: 'Not in Device Log',
    2: 'Other Failure',
  })
}

// CS06

export function parseActivateFirmwareCommand(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Activate Firmware Command')
  const indent = ' '
  parseDerOctetString(ctx, s, `${indent}Manufacturer Image Hash`)
  parseSeqNumber(ctx, s, `${indent}Originator Counter`)
  if (s.index < s.end) {
    parseGeneralizedTime(ctx, s, `${indent}Execution Date Time`)
  }
}

export function parseActivateFirmwareResponse(ctx: Context, x: Slice) {
  if (isPresent(x, 5)) {
    parseNull(ctx, x, 'Command Accepted')
  } else {
    parseActivateFirmwareExecutionOutcome(ctx, x, '')
  }
}

export function parseActivateFirmwareAlert(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Activate Firmware Alert')
  const indent = ' '
  parseAsn1AlertCode(ctx, s, indent)
  parseGeneralizedTime(ctx, s, `${indent}Execution Date Time`)
  parseSeqNumber(ctx, s, `${indent}Originator Counter`)
  parseActivateFirmwareExecutionOutcome(ctx, s, indent)
}

export function parseActivateFirmwareExecutionOutcome(
  ctx: Context,
  x: Slice,
  indent: string
) {
  const s = parseSequence(ctx, x, `${indent}Execution Outcome`)
  indent = indent + ' '
  parseInteger(ctx, s, `${indent}Response Code`, {
    0: 'Success',
    1: 'No Image Held',
    2: 'Hash Mismatch',
    3: 'Activation Failure',
  })
  parseDerOctetString(ctx, s, `${indent}Firmware Version`)
}

// CS07

export function parseReadDeviceJoinDetailsCommand(ctx: Context, x: Slice) {
  parseNull(ctx, x, 'Read Device Join Details Command')
}

export function parseReadDeviceJoinDetailsResponse(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Read Device Join Details Response')
  const indent = ' '
  parseInteger(ctx, s, `${indent}Response Code`, {
    0: 'Success',
    1: 'Read Failure',
  })
  if (s.index < s.end) {
    parseSequenceOf(ctx, s, `${indent}Device Log Entries`, parseDeviceLogEntry)
  }
}

export function parseDeviceLogEntry(ctx: Context, x: Slice, name: string) {
  const s = parseSequence(ctx, x, `${name}Device Log Entry`)
  const indent = (name.match(/^ */)?.[0] ?? '') + ' '
  parseDerOctetString(ctx, s, `${indent}Device Id`)
  parseDeviceType(ctx, s, indent)
}

// CCS08

export function parseFirmwareTransferAlert(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Firmware Transfer Alert')
  const indent = ' '
  parseAsn1AlertCode(ctx, s, indent)
  parseGeneralizedTime(ctx, s, `${indent}Execution Date Time`)
  parseDerOctetString(ctx, s, `${indent}Entity Id`)
  parseDerOctetString(ctx, s, `${indent}Firmware Version`)
  parseInteger(ctx, s, `${indent}Response Code`, {
    0: 'Success',
    1: 'Image Discarded',
    2: 'Hardware Version Mismatch',
    3: 'File Transfer Failure',
  })
}

// CS08

export function parseReadPPMIDHCALCSFirmwareVersionCommand(
  ctx: Context,
  x: Slice
) {
  parseNull(ctx, x, 'Read PPMID HCALCS Firmware version')
}

export function parseReadPPMIDHCALCSFirmwareVersionResponse(
  ctx: Context,
  x: Slice
) {
  const s = parseSequence(ctx, x, 'Read Device Join Details Response')
  const indent = ' '
  parseDerOctetString(ctx, s, `${indent}Firmware Version`)
  parseInteger(ctx, s, `${indent}Response Code`, {
    0: 'Read Success',
    1: 'Read Failure',
  })
}

export function parseReadPPMIDHCALCSFirmwareVersionAlert(
  ctx: Context,
  x: Slice
) {
  const s = parseSequence(ctx, x, 'Read PPMID/HCALCS Firmware Version')
  const indent = ' '
  parseAsn1AlertCode(ctx, s, indent)
  parseGeneralizedTime(ctx, s, `${indent}Execution Date Time`)
  parseDerOctetString(ctx, s, `${indent}Firmware Version`)
  parseInteger(ctx, s, `${indent}Activate image`, {
    0: 'Success',
    1: 'Failure',
  })
}

// GCS28

export function parseSetTimeCommand(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Set Time Command')
  const indent = ' '
  parseGeneralizedTime(ctx, s, `${indent}Validity Interval Start`)
  parseGeneralizedTime(ctx, s, `${indent}Validity Interval End`)
}

export function parseSetTimeResponse(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Set Time Response')
  const indent = ' '
  parseGeneralizedTime(ctx, s, `${indent}Device Time`)
  parseInteger(ctx, s, `${indent}Device Time Status`, {
    0: 'Reliable',
    1: 'Invalid',
    2: 'Unreliable',
  })
}

// GCS59

export function parseGpfDeviceLogRestoreCommand(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'GPF Device Log Restore Command')
  const indent = ' '
  parseSequenceOf(ctx, s, `${indent}Device Log Entries`, parseDeviceLogEntry)
}

export function parseGpfDeviceLogRestoreResponse(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'GPF Device Log Restore Response')
  const indent = ' '
  parseSequenceOf(
    ctx,
    s,
    `${indent}Restore Outcomes`,
    parseGpfDeviceLogRestoreOutcome
  )
}

function parseGpfDeviceLogRestoreOutcome(ctx: Context, x: Slice, name: string) {
  const s = parseSequence(ctx, x, `${name}Restore Outcome`)
  const indent = (name.match(/^ */)?.[0] ?? '') + ' '
  parseDeviceLogEntry(ctx, s, indent)
  const joinResponseCodes = {
    0: 'Success',
    1: 'Invalid Message Code for Join Method and Role',
    2: 'Invalid Join Method and Role',
    3: 'Incompatible with Existing Entry',
    4: 'Device Log Full',
    5: 'Write Failure',
    6: 'Key Agreement No Resources',
    7: 'Key Agreement Unknown Issuer',
    8: 'Key Agreement Unsupported Suite',
    9: 'Key Agreement Bad Message',
    10: 'Key Agreement Bad Key Confirm',
    11: 'Invalid or Missing Certificate',
  }
  parseInteger(ctx, s, `${indent}Join Response Code`, joinResponseCodes)
}

// GCS62

export function parseGpfDeviceLogBackupAlert(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'GPF Device Log Backup Alert')
  const indent = ' '
  parseAsn1AlertCode(ctx, s, indent)
  parseGeneralizedTime(ctx, s, `${indent}Backup Date Time`)
  parseSequenceOf(ctx, s, `${indent}Device Log Entries`, parseDeviceLogEntry)
}

// GBCS ASN.1 definitions used by multiple use cases

function parseDeviceType(ctx: Context, x: Slice, indent: string) {
  parseInteger(ctx, x, `${indent}Device Type`, {
    0: 'GSME',
    1: 'ESME',
    2: 'CHF',
    3: 'GPF',
    4: 'HCALCS',
    5: 'PPMID',
    6: 'Type 2',
  })
}

function parseTrustAnchorCellIdentifier(ctx: Context, x: Slice, name: string) {
  const indent = (name.match(/^ */)?.[0] ?? '') + ' '
  const s = parseSequence(ctx, x, name)
  parseRemotePartyRole(ctx, s, indent)
  parseKeyUsage(ctx, s, indent)
  parseCellUsage(ctx, s, indent)
}

function parseRemotePartyRole(ctx: Context, x: Slice, name: string) {
  const values = {
    0: 'Root',
    1: 'Recovery',
    2: 'Supplier',
    3: 'Network Operator',
    4: 'Access Control Broker',
    5: 'Transitional Change of Supplier',
    6: 'WAN Provider',
    7: 'Issuing Authority',
    127: 'Other',
  }
  parseInteger(ctx, x, `${name}Remote Party Role`, values)
}

function parseKeyUsage(ctx: Context, x: Slice, indent: string) {
  const bits: Record<number, string> = {
    0: 'Digital Signature',
    4: 'Key Agreement',
    5: 'Key Cert Sign',
    6: 'CRL Sign',
  }
  const length = x.input.byte(x.index + 1)
  const bitstring = x.input.byte(x.index + 3)
  let notes = ''
  for (let i = 0; i < 8; i++) {
    if (bitstring & (0x80 >> i)) {
      if (bits[i]) {
        if (notes) notes += ' '
        notes += bits[i]
      }
    }
  }
  putBytes(ctx, `${indent}Key Usage`, getBytes(x, 2 + length), notes)
}

// CellUsage ::= INTEGER { management (0), prePaymentTopUp (1) } DEFAULT management
function parseCellUsage(ctx: Context, x: Slice, indent: string) {
  if (
    x.index + 2 < x.end &&
    x.input.byte(x.index) === 2 &&
    x.input.byte(x.index + 1) === 1 &&
    x.input.byte(x.index + 2) === 1
  ) {
    putBytes(ctx, `${indent}Cell Usage`, getBytes(x, 3), 'Prepayment Top Up')
  } else {
    putBytes(ctx, `${indent}Cell Usage`, getBytes(x, 0), 'Management (DEFAULT)')
  }
}

function parseSeqNumber(ctx: Context, x: Slice, name: string) {
  const length = x.input.byte(x.index + 1)
  const bytes = getBytes(x, 2 + length)
  const value = { input: bytes.input, index: bytes.index + 2, end: bytes.end }
  putBytes(ctx, name, bytes, getDecimalString(value))
}

function parseCredentialsReplacementMode(
  ctx: Context,
  x: Slice,
  indent: string
) {
  const values = {
    2: 'Supplier by Supplier',
    3: 'Network Operator by Network Operator',
    4: 'ACB by ACB',
    5: 'WAN Provider by WAN Provider',
    6: 'TransCoS by TransCoS',
    7: 'Supplier by TransCoS',
    8: 'Any Except Abnormal Root by Recovery',
    9: 'Any by Contingency',
  }
  parseInteger(ctx, x, `${indent}Credentials Replacement Mode`, values)
}

function parseAuthorisingRemotePartyControl(
  ctx: Context,
  x: Slice,
  indent: string
) {
  const s = parseSequence(ctx, x, `${indent}Authorising Remote Party Control`)
  indent = indent + ' '
  parseCredentialsReplacementMode(ctx, s, indent)
  if (isPresent(s, 0x80))
    parseDerOctetString(ctx, s, `${indent}Plaintext Symmetric Key`)
  if (isPresent(s, 0x81))
    parseInteger(ctx, s, `${indent}Apply Time Based CPV Checks`, {
      0: 'Apply',
      1: 'Disapply',
    })
  if (isPresent(s, 0xa2))
    parseTrustAnchorCellIdentifier(
      ctx,
      s,
      `${indent}Authorising Remote Party TA Cell Identifier`
    )
  parseSeqNumber(ctx, s, `${indent}Authorising Remote Party Seq Number`)
  if (isPresent(s, 0x84))
    parseSeqNumber(ctx, s, `${indent}New Remote Party Floor Seq Number`)
  if (isPresent(s, 0xa5))
    parseSequenceOf(
      ctx,
      s,
      `${indent}New Remote Party Specialist Floor Seq Number`,
      parseSpecialistSeqNumber
    )
  if (isPresent(s, 0xa6))
    parseSequenceOf(
      ctx,
      s,
      `${indent}Other Remote Party Seq Number Changes`,
      parseRemotePartySeqNumberChange
    )
}

function parseSpecialistSeqNumber(ctx: Context, x: Slice, name: string) {
  const s = parseSequence(ctx, x, `${name}Specialist Seq Number`)
  const indent = (name.match(/^ */)?.[0] ?? '') + ' '
  parseInteger(ctx, s, `${indent}Seq Number Usage`, { 0: 'Prepayment Top Up' })
  parseSeqNumber(ctx, s, `${indent}Seq Number`)
}

function parseRemotePartySeqNumberChange(ctx: Context, x: Slice, name: string) {
  const s = parseSequence(ctx, x, `${name}Remote Party Seq Number Change`)
  const indent = (name.match(/^ */)?.[0] ?? '') + ' '
  parseRemotePartyRole(ctx, s, indent)
  parseSeqNumber(ctx, s, `${indent}Floor Seq Number`)
  if (isPresent(s, 0x30))
    parseSequenceOf(
      ctx,
      s,
      `${indent}Specialist Floor Seq Number`,
      parseSpecialistSeqNumber
    )
}

function parseTrustAnchorReplacement(ctx: Context, x: Slice, name: string) {
  const s = parseSequence(ctx, x, `${name}Trust Anchor Replacement`)
  const indent = (name.match(/^ */)?.[0] ?? '') + ' '
  parseCertificate(ctx, s, indent)
  parseTrustAnchorCellIdentifier(ctx, s, `${indent}Target Trust Anchor Cell`)
}

// StatusCode ::= ENUMERATED { success (0), ... }
// Used in the CS02a and CS02b responses
function parseStatusCode(ctx: Context, x: Slice, indent: string) {
  const values = {
    0: 'Success',
    5: 'Bad Certificate',
    10: 'No Trust Anchor',
    17: 'Insufficient Memory',
    25: 'Trust Anchor Not Found',
    30: 'Resources Busy',
    127: 'Other',
  }
  parseEnumerated(ctx, x, `${indent}Status Code`, values)
}

export function parseCertificate(ctx: Context, x: Slice, name?: string) {
  const lenSz = parseLength(x, 1)
  const size = 1 + lenSz.size + lenSz.length
  putBytes(ctx, name ?? 'Certificate', getBytes(x, size))
}

// ASN.1 Types

export function parseSequence(ctx: Context, x: Slice, name: string) {
  const lenSz = parseLength(x, 1)
  putBytes(ctx, name, getBytes(x, 1 + lenSz.size))
  return getBytes(x, lenSz.length)
}

function parseSequenceOf(
  ctx: Context,
  x: Slice,
  name: string,
  parse: (ctx: Context, x: Slice, name: string) => void
) {
  const indent = name.match(/^ */)?.[0] ?? ''
  const s = parseSequence(ctx, x, name)
  let i = 0
  while (s.index < s.end) {
    parse(ctx, s, `${indent} [${i}] `)
    i++
  }
}

function parseInteger(
  ctx: Context,
  x: Slice,
  name: string,
  values: Record<number, string>
) {
  let value = 0
  const length = x.input.byte(x.index + 1)
  value = parseNumber(x, length, 2)
  putBytes(ctx, name, getBytes(x, 2 + length), values?.[value] ?? String(value))
}

function parseAsn1AlertCode(ctx: Context, x: Slice, indent: string) {
  let alertCode = 0
  const length = x.input.byte(x.index + 1)
  alertCode = parseNumber(x, length, 2)
  putBytes(
    ctx,
    `${indent}Alert Code`,
    getBytes(x, 2 + length),
    getAlertCodeName(alertCode)
  )
}

function parseEnumerated(
  ctx: Context,
  x: Slice,
  name: string,
  values: Record<number, string>
) {
  parseInteger(ctx, x, name, values)
}

function parseDerOctetString(ctx: Context, x: Slice, name: string) {
  const lenSz = parseLength(x, 1)
  putBytes(ctx, name, getBytes(x, 1 + lenSz.size + lenSz.length))
}

function parseGeneralizedTime(ctx: Context, x: Slice, name: string) {
  const length = x.input.byte(x.index + 1)
  let time = ''
  for (let i = 0; i < length; i++) {
    const c = x.input.byte(x.index + 2 + i)
    if (i === 4 || i === 6) time += '-'
    else if (i === 8 || i === 14) time += ' '
    else if (i === 10 || i === 12) time += ':'
    time += String.fromCharCode(c)
  }
  putBytes(ctx, name, getBytes(x, 2 + length), time)
}

function parseNull(ctx: Context, x: Slice, name: string) {
  putBytes(ctx, name, getBytes(x, 2))
}

function isPresent(x: Slice, tag: number) {
  return x.index < x.end && x.input.byte(x.index) === tag
}
