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
  parseTrustAnchorCellIdentifier(
    ctx,
    s,
    'Authorising Remote Party TA Cell Identifier'
  )
  parseSequenceOf(
    ctx,
    s,
    'Remote Party Roles Credentials Required',
    parseRemotePartyRole
  )
}

export function parseProvideSecurityCredentialDetailsResponse(
  ctx: Context,
  x: Slice
) {
  const sequenceOf = parseSequence(
    ctx,
    x,
    'Provide Security Credential Details Response'
  )
  while (sequenceOf.index < sequenceOf.end) {
    const rpDetails = parseSequence(ctx, sequenceOf, 'Remote Party Details')
    parseRemotePartyRole(ctx, rpDetails)
    parseStatusCode(ctx, rpDetails)
    if (rpDetails.index < rpDetails.end) {
      parseSeqNumber(ctx, rpDetails, 'Current Seq Number')
      const tacDetails = parseSequence(
        ctx,
        rpDetails,
        'Trust Anchor Cell Details'
      )
      while (tacDetails.index < tacDetails.end) {
        const contents = parseSequence(
          ctx,
          tacDetails,
          'Trust Anchor Cell Contents'
        )
        parseKeyUsage(ctx, contents)
        parseCellUsage(ctx, contents)
        parseDerOctetString(ctx, contents, 'Subject Unique ID')
        parseDerOctetString(ctx, contents, 'Subject Key Identifier')
      }
    }
  }
}

// CS02b Update Security Credentials

export function parseUpdateSecurityCredentialsCommand(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Update Security Credentials Command')
  parseAuthorisingRemotePartyControl(ctx, s)
  parseSequenceOf(ctx, s, 'Replacements', parseTrustAnchorReplacement)
  parseSequenceOf(ctx, s, 'Certification Path Certificates', parseCertificate)
  if (isPresent(s, 0x18)) parseGeneralizedTime(ctx, s, 'Execution Date Time')
}

export function parseUpdateSecurityCredentialsResponse(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Update Security Credentials Response')
  parseNull(ctx, s, 'Command Accepted')
  if (isPresent(s, 0x30)) parseUpdateSecurityCredentialsExecutionOutcome(ctx, s)
}

export function parseUpdateSecurityCredentialsAlert(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Update Security Credentials Alert')
  parseAsn1AlertCode(ctx, s)
  parseGeneralizedTime(ctx, s, 'Execution Date Time')
  parseUpdateSecurityCredentialsExecutionOutcome(ctx, s)
}

export function parseUpdateSecurityCredentialsExecutionOutcome(
  ctx: Context,
  x: Slice
) {
  const s = parseSequence(ctx, x, 'Execution Outcome')
  parseSeqNumber(ctx, s, 'Authorising Remote Party Seq Number')
  parseCredentialsReplacementMode(ctx, s)
  parseSequenceOf(
    ctx,
    s,
    'Remote Party Seq Number Changes',
    parseRemotePartySeqNumberChange
  )
  parseSequenceOf(ctx, s, 'Replacement Outcomes', parseReplacementOutcome)
}

export function parseReplacementOutcome(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Replacement Outcome')
  parseTrustAnchorCellIdentifier(ctx, s, ' Affected Trust Anchor Cell')
  parseStatusCode(ctx, s)
  parseDerOctetString(ctx, s, ' Existing Subject Unique ID')
  parseDerOctetString(ctx, s, ' Existing Subject Key ID')
  parseDerOctetString(ctx, s, ' Replacing Subject Unique ID')
  parseDerOctetString(ctx, s, ' Replacing Subject Key ID')
}

// CS02c Issue Security Credentials

export function parseIssueSecurityCredentialsCommand(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Issue Security Credentials Command')
  parseKeyUsage(ctx, s)
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
  parseKeyUsage(ctx, s)
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
  parseInteger(ctx, s, ' Join Method and Role', {
    0: 'Method A Initiator',
    1: 'Method A Responder',
    2: 'Method B',
    3: 'Method C',
  })
  parseDerOctetString(ctx, s, ' Entity Id')
  parseDeviceType(ctx, s)
  if (s.index < s.end) {
    parseCertificate(ctx, s)
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
    0: 'Succes',
    1: 'Not in Device Log',
    2: 'Other Failure',
  })
}

// CS06

export function parseActivateFirmwareCommand(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Activate Firmware Command')
  parseDerOctetString(ctx, s, 'Manufacturer Image Hash')
  parseSeqNumber(ctx, s, 'Originator Counter')
  if (s.index < s.end) {
    parseGeneralizedTime(ctx, s, 'Execution Date Time')
  }
}

export function parseActivateFirmwareResponse(ctx: Context, x: Slice) {
  if (isPresent(x, 5)) {
    parseNull(ctx, x, 'Command Accepted')
  } else {
    parseActivateFirmwareExecutionOutcome(ctx, x)
  }
}

export function parseActivateFirmwareAlert(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Activate Firmware Alert')
  parseAsn1AlertCode(ctx, s)
  parseGeneralizedTime(ctx, s, 'Execution Date Time')
  parseSeqNumber(ctx, s, 'Originator Counter')
  parseActivateFirmwareExecutionOutcome(ctx, s)
}

export function parseActivateFirmwareExecutionOutcome(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Execution Outcome')
  parseInteger(ctx, s, 'Response Code', {
    0: 'Success',
    1: 'No Image Held',
    2: 'Hash Mismatch',
    3: 'Activation Failure',
  })
  parseDerOctetString(ctx, s, 'Firmware Version')
}

// CS07

export function parseReadDeviceJoinDetailsCommand(ctx: Context, x: Slice) {
  parseNull(ctx, x, 'Read Device Join Details Command')
}

export function parseReadDeviceJoinDetailsResponse(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Read Device Join Details Response')
  parseInteger(ctx, s, 'Response Code', { 0: 'Success', 1: 'Read Failure' })
  if (s.index < s.end) {
    parseSequenceOf(ctx, s, 'Device Log Entries', parseDeviceLogEntry)
  }
}

export function parseDeviceLogEntry(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Device Log Entry')
  parseDerOctetString(ctx, s, 'Device Id')
  parseDeviceType(ctx, s)
}

// CCS08

export function parseFirmwareTransferAlert(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Firmware Transfer Alert')
  parseAsn1AlertCode(ctx, s)
  parseGeneralizedTime(ctx, s, 'Execution Date Time')
  parseDerOctetString(ctx, s, 'Entity Id')
  parseDerOctetString(ctx, s, 'Firmware Version')
  parseInteger(ctx, s, 'Response Code', {
    0: 'Success',
    1: 'Image Discarded',
    2: 'Hardeware Version Mismatch',
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
  parseDerOctetString(ctx, s, 'Firmware Version')
  parseInteger(ctx, s, 'Response Code', {
    0: 'Read Success',
    1: 'Read Failure',
  })
}

export function parseReadPPMIDHCALCSFirmwareVersionAlert(
  ctx: Context,
  x: Slice
) {
  const s = parseSequence(ctx, x, 'Read PPMID/HCALCS Firmware Version')
  parseAsn1AlertCode(ctx, s)
  parseGeneralizedTime(ctx, s, 'Execution Date Time')
  parseDerOctetString(ctx, s, 'Firmware Version')
  parseInteger(ctx, s, 'Activate image', { 0: 'Success', 1: 'Failure' })
}
// GCS28

export function parseSetTimeCommand(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Set Time Command')
  parseGeneralizedTime(ctx, s, 'Validity Interval Start')
  parseGeneralizedTime(ctx, s, 'Validity Interval End')
}

export function parseSetTimeResponse(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Set Time Response')
  parseGeneralizedTime(ctx, s, 'Device Time')
  parseInteger(ctx, s, 'Device Time Status', {
    0: 'Reliable',
    1: 'Invalid',
    2: 'Unreliable',
  })
}

// GCS59

export function parseGpfDeviceLogRestoreCommand(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'GPF Device Log Restore Command')
  parseSequenceOf(ctx, s, 'Device Log Entries', parseDeviceLogEntry)
}

export function parseGpfDeviceLogRestoreResponse(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'GPF Device Log Restore Response')
  parseSequenceOf(ctx, s, 'Restore Outcomes', parseGpfDeviceLogRestoreOutcome)
}

function parseGpfDeviceLogRestoreOutcome(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Restore Outcome')
  parseDeviceLogEntry(ctx, s)
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
  parseInteger(ctx, s, 'Join Response Code', joinResponseCodes)
}

// GCS62

export function parseGpfDeviceLogBackupAlert(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'GPF Device Log Backup Alert')
  parseAsn1AlertCode(ctx, s)
  parseGeneralizedTime(ctx, s, 'Backup Date Time')
  parseSequenceOf(ctx, s, 'Device Log Entries', parseDeviceLogEntry)
}

// GBCS ASN.1 definitions used by multiple use cases

function parseDeviceType(ctx: Context, x: Slice) {
  parseInteger(ctx, x, ' Device Type', {
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
  const s = parseSequence(ctx, x, name)
  parseRemotePartyRole(ctx, s)
  parseKeyUsage(ctx, s)
  parseCellUsage(ctx, s)
}

function parseRemotePartyRole(ctx: Context, x: Slice) {
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
  parseInteger(ctx, x, '  Remote Party Role', values)
}

function parseKeyUsage(ctx: Context, x: Slice) {
  const bits: Record<number, string> = {
    0: 'Digital Signature',
    4: 'Key Agreement',
    5: 'Key Cert Sign',
    6: 'CRL Sign',
  }
  const length = x.input[x.index + 1]
  const bitstring = x.input[x.index + 3]
  let notes = ''
  for (let i = 0; i < 8; i++) {
    if (bitstring & (0x80 >> i)) {
      if (bits[i]) {
        if (notes) notes += ' '
        notes += bits[i]
      }
    }
  }
  putBytes(ctx, '  Key Usage', getBytes(x, 2 + length), notes)
}

// CellUsage ::= INTEGER { management (0), prePaymentTopUp (1) } DEFAULT management
function parseCellUsage(ctx: Context, x: Slice) {
  if (
    x.index + 2 < x.end &&
    x.input[x.index] === 2 &&
    x.input[x.index + 1] === 1 &&
    x.input[x.index + 2] === 1
  ) {
    putBytes(ctx, '  Cell Usage', getBytes(x, 3), 'Prepayment Top Up')
  } else {
    putBytes(
      ctx,
      '  Cell Usage',
      { input: new Uint8Array(), index: 0, end: 0 },
      'Management (DEFAULT)'
    )
  }
}

function parseSeqNumber(ctx: Context, x: Slice, name: string) {
  const length = x.input[x.index + 1]
  const bytes = getBytes(x, 2 + length)
  const value = { input: bytes.input, index: bytes.index + 2, end: bytes.end }
  putBytes(ctx, name, bytes, getDecimalString(value))
}

function parseCredentialsReplacementMode(ctx: Context, x: Slice) {
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
  parseInteger(ctx, x, ' Credentials Replacement Mode', values)
}

function parseAuthorisingRemotePartyControl(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Authorising Remote Party Control')
  parseCredentialsReplacementMode(ctx, s)
  if (isPresent(s, 0x80))
    parseDerOctetString(ctx, s, ' Plaintext Symmetric Key')
  if (isPresent(s, 0x81))
    parseInteger(ctx, s, ' Apply Time Based CPV Checks', {
      0: 'Apply',
      1: 'Disapply',
    })
  if (isPresent(s, 0xa2))
    parseTrustAnchorCellIdentifier(
      ctx,
      s,
      ' Authorising Remote Party TA Cell Identifier'
    )
  parseSeqNumber(ctx, s, ' Authorising Remote Party Seq Number')
  if (isPresent(s, 0x84))
    parseSeqNumber(ctx, s, ' New Remote Party Floor Seq Number')
  if (isPresent(s, 0xa5))
    parseSequenceOf(
      ctx,
      s,
      ' New Remote Party Specialist Floor Seq Number',
      parseSpecialistSeqNumber
    )
  if (isPresent(s, 0xa6))
    parseSequenceOf(
      ctx,
      s,
      ' Other Remote Party Seq Number Changes',
      parseRemotePartySeqNumberChange
    )
}

function parseSpecialistSeqNumber(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, '  Specialist Seq Number')
  parseInteger(ctx, s, '   Seq Number Usage', { 0: 'Prepayment Top Up' })
  parseSeqNumber(ctx, s, '   Seq Number')
}

function parseRemotePartySeqNumberChange(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, ' Remote Party Seq Number Change')
  parseRemotePartyRole(ctx, s)
  parseSeqNumber(ctx, s, '  Floor Seq Number')
  if (isPresent(s, 0x30))
    parseSequenceOf(
      ctx,
      s,
      '  Specialist Floor Seq Number',
      parseSpecialistSeqNumber
    )
}

function parseTrustAnchorReplacement(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Trust Anchor Replacement')
  parseCertificate(ctx, s)
  parseTrustAnchorCellIdentifier(ctx, s, ' Target Trust Anchor Cell')
}

// StatusCode ::= ENUMERATED { success (0), ... }
// Used in the CS02a and CS02b responses
function parseStatusCode(ctx: Context, x: Slice) {
  const values = {
    0: 'Success',
    5: 'Bad Certificate',
    10: 'No Trust Anchor',
    17: 'Insufficient Memory',
    25: 'Trust Anchor Not Found',
    30: 'Resources Busy',
    127: 'Other',
  }
  parseEnumerated(ctx, x, ' Status Code', values)
}

export function parseCertificate(ctx: Context, x: Slice, name?: string) {
  const lenSz = parseLength(x, 1)
  const size = 1 + lenSz.size + lenSz.length
  putBytes(ctx, name ?? ' Certificate', getBytes(x, size))
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
  parse: (ctx: Context, x: Slice) => void
) {
  const s = parseSequence(ctx, x, name)
  while (s.index < s.end) {
    parse(ctx, s)
  }
}

function parseInteger(
  ctx: Context,
  x: Slice,
  name: string,
  values: Record<number, string>
) {
  let value = 0
  const length = x.input[x.index + 1]
  value = parseNumber(x, length, 2)
  putBytes(ctx, name, getBytes(x, 2 + length), values?.[value] ?? String(value))
}

function parseAsn1AlertCode(ctx: Context, x: Slice) {
  let alertCode = 0
  const length = x.input[x.index + 1]
  alertCode = parseNumber(x, length, 2)
  putBytes(
    ctx,
    'Alert Code',
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
  const length = x.input[x.index + 1]
  let time = ''
  for (let i = 0; i < length; i++) {
    const c = x.input[x.index + 2 + i]
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
  return x.index < x.end && x.input[x.index] === tag
}
