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

import { parseSequence } from './asn1'
import {
  parseLength,
  parseMeterIntegrityIssueWarning,
  parseNumber,
  parseCounter,
  parseMessageCode,
  parseCraFlag,
} from './common'
import { CipherInfo, Context, putBytes, putUnparsedBytes } from './context'
import { decryptGbcsData } from './crypto'
import {
  daysInWeek,
  getAlertCodeName,
  getBytes,
  monthsInYear,
  Slice,
} from './util'

// DLMS Payloads

interface CosemClass {
  name: string
  attributes: string[]
  methods: string[]
  instances: Record<number, string>
}

export function parseDlmsAccessRequest(ctx: Context, x: Slice) {
  putBytes(ctx, 'DLMS Access Request', getBytes(x, 6))
  parseDlmsSequenceOf(
    ctx,
    x,
    'List of Access Request Specifications',
    parseDlmsAccessRequestSpecification
  )
  // TODO: check for IC 0x001E (Data Protection), Method 1 (Get Protected Attributes)
  parseDlmsSequenceOf(ctx, x, 'List of Data', parseDlmsData)
}

export function parseDlmsAccessResponse(
  ctx: Context,
  x: Slice,
  messageCode: number
) {
  putBytes(ctx, 'DLMS Access Response', getBytes(x, 7))
  switch (messageCode) {
    case 0x0027: // ECS17b
    case 0x0029: // ECS17d
    case 0x002a: // ECS17e
    case 0x002d: // ECS19
    case 0x002f: // ECS20b
    case 0x0030: // ECS20c
    case 0x0033: // ECS21a
    case 0x0034: // ECS21b
    case 0x0037: // ECS22b
    case 0x0060: // ECS66
      parseDlmsSequenceOf(
        ctx,
        x,
        'List of Access Response Data',
        parseDlmsProtectedAttributesResponse
      )
      break
    default:
      parseDlmsSequenceOf(ctx, x, 'List of Access Response Data', parseDlmsData)
      break
  }
  parseDlmsSequenceOf(
    ctx,
    x,
    'List of Access Response Specification',
    parseDlmsAccessResponseSpecification
  )
}

export function parseDlmsDataNotificationGbcsAlert(ctx: Context, x: Slice) {
  putBytes(ctx, 'DLMS Data Notification', getBytes(x, 8))
  parseDlmsAlertCode(ctx, x)
  parseDlmsOctetString(ctx, x, 'Time Stamp', true)
  while (x.index < x.end) {
    parseDlmsData(ctx, x)
  }
}

function parseDlmsAccessRequestSpecification(
  ctx: Context,
  x: Slice,
  idx: string
) {
  const choice = x.input[x.index]
  if (choice === 1) {
    putBytes(
      ctx,
      ' Access Request Specification',
      getBytes(x, 1),
      'Access Request Get ' + idx
    )
    parseDlmsCosemAttributeDescriptor(ctx, x)
  } else if (choice === 2) {
    putBytes(
      ctx,
      ' Access Request Specification',
      getBytes(x, 1),
      'Access Request Set ' + idx
    )
    parseDlmsCosemAttributeDescriptor(ctx, x)
  } else if (choice === 3) {
    putBytes(
      ctx,
      ' Access Request Specification',
      getBytes(x, 1),
      'Access Request Action ' + idx
    )
    parseDlmsCosemMethodDescriptor(ctx, x)
  } else if (choice === 4) {
    putBytes(
      ctx,
      ' Access Request Specification',
      getBytes(x, 1),
      'Access Request Get with Selection ' + idx
    )
    parseDlmsCosemAttributeDescriptor(ctx, x)
    parseDlmsSelectiveAccessDescriptor(ctx, x)
  } else {
    throw 'TODO: Access-Request-Specification CHOICE ' + choice
  }
}

function parseDlmsAccessResponseSpecification(
  ctx: Context,
  x: Slice,
  idx: string
) {
  const choice = x.input[x.index]
  if (choice === 1) {
    putBytes(
      ctx,
      'Access Response Specification',
      getBytes(x, 1),
      'Access Response Get ' + idx
    )
    parseDlmsDataAccessResult(ctx, x)
  } else if (choice === 2) {
    putBytes(
      ctx,
      'Access Response Specification',
      getBytes(x, 1),
      'Access Response Set ' + idx
    )
    parseDlmsDataAccessResult(ctx, x)
  } else if (choice === 3) {
    putBytes(
      ctx,
      'Access Response Specification',
      getBytes(x, 1),
      'Access Response Action ' + idx
    )
    parseDlmsActionResult(ctx, x)
  } else {
    throw 'TODO: Access-Response-Specification CHOICE ' + choice
  }
}

export function parseDlmsFutureDatedAlert(ctx: Context, x: Slice) {
  putBytes(ctx, 'DLMS Data Notification (Future Dated Alert)', getBytes(x, 8))
  parseDlmsAlertCode(ctx, x)
  parseDlmsOctetString(ctx, x, 'Time Stamp', true)
  putBytes(ctx, 'Future Dated Alert Payload', getBytes(x, 2))
  parseMessageCode(ctx, 'Message Code', x)
  parseCounter(ctx, 'Originator Counter', x)
  parseDlmsCosemAttributeDescriptor(ctx, x)
}

export function parseDlmsFirmwareDistributionReceiptAlert(
  ctx: Context,
  x: Slice
) {
  putBytes(ctx, 'DLMS Data Notification', getBytes(x, 8))
  parseDlmsAlertCode(ctx, x)
  parseDlmsOctetString(ctx, x, 'Time Stamp', true)
  parseDlmsOctetString(ctx, x, 'Calculated Manufacturer Hash', true)
}

export function parseDlmsBillingDataLogAlert(ctx: Context, x: Slice) {
  putBytes(ctx, 'DLMS Data Notification', getBytes(x, 8))
  parseDlmsAlertCode(ctx, x)
  parseDlmsOctetString(ctx, x, 'Time Stamp', true)
  parseDlmsProtectedData(ctx, x)
}

export function parseDlmsMeterIntegrityIssueWarningAlert(
  ctx: Context,
  x: Slice
) {
  putBytes(ctx, 'DLMS Data Notification', getBytes(x, 8))
  parseDlmsAlertCode(ctx, x)
  parseDlmsOctetString(ctx, x, 'Time Stamp', true)
  putBytes(ctx, 'DLMS Use Case Specific Content', getBytes(x, 2))
  parseMeterIntegrityIssueWarning(ctx, x)
}

function parseProtectionParameters(ctx: Context, x: Slice) {
  putBytes(ctx, 'Protection Parameters', getBytes(x, 4))
  parseDlmsEnum(ctx, x, ' Protection Type', true, {
    2: 'Authentication and Encryption',
  })
  putBytes(ctx, ' Protection Options', getBytes(x, 2))
  const cipherInfo: CipherInfo = {
    origCounter: x.input.subarray(x.index + 3, x.index + 11),
    origSysTitle: x.input.subarray(x.index + 13, x.index + 21),
    recipSysTitle: x.input.subarray(x.index + 23, x.index + 31),
  }
  putBytes(ctx, ' Transaction Id', getBytes(x, 11))
  putBytes(ctx, ' Originator System Title', getBytes(x, 10))
  putBytes(ctx, ' Recipient System Title', getBytes(x, 10))
  putBytes(ctx, ' Other Information', getBytes(x, 2))
  putBytes(ctx, ' Key Info', getBytes(x, 2))
  parseDlmsEnum(ctx, x, '  Key Info Type', true, { 2: 'Agreed Key' })
  putBytes(ctx, '  Agreed Key Info Options', getBytes(x, 2))
  putBytes(ctx, '   Key Parameters', getBytes(x, 3), 'C(0e, 2s ECC CDH)')
  putBytes(ctx, '   Key Ciphered Data', getBytes(x, 2))
  return cipherInfo
}

function parseDlmsProtectedAttributesResponse(ctx: Context, x: Slice) {
  putBytes(ctx, 'Get Protected Attributes Response', getBytes(x, 2))
  parseDlmsProtectedData(ctx, x)
}

function parseDlmsProtectedData(ctx: Context, x: Slice) {
  /*const cipherInfo = */ parseProtectionParameters(ctx, x)
  const lenSz = parseLength(x, 1)
  const len = lenSz.length
  const off = lenSz.size + 1
  putBytes(ctx, 'Protected Attributes', getBytes(x, off))
  const y = getBytes(x, len)
  putBytes(ctx, ' Security Header', getBytes(y, 5))
  const ciphertextAndTag = y.input.subarray(y.index, y.index + len - 5)
  putBytes(ctx, ' Encrypted DLMS Payload', getBytes(y, len - 5 - 12))
  putBytes(ctx, ' AE MAC', getBytes(y, 12))

  decryptGbcsData(ctx, ciphertextAndTag, function (yy: Slice) {
    parseDlmsData(ctx, yy)
    putUnparsedBytes(yy)
  })
}

function parseDlmsSequenceOf(
  ctx: Context,
  x: Slice,
  name: string,
  parse: (ctx: Context, x: Slice, name: string) => void
) {
  const n = x.input[x.index]
  putBytes(ctx, name, getBytes(x, 1))
  for (let i = 0; i < n; i++) {
    parse(ctx, x, '[' + i + '] ')
  }
}

function parseDlmsData(ctx: Context, x: Slice, indent?: string) {
  indent = indent ?? ''
  const choice = x.input[x.index]
  if (choice === 0) {
    putBytes(ctx, indent + 'Null', getBytes(x, 1))
  } else if (choice === 1) {
    const n = x.input[x.index + 1]
    putBytes(
      ctx,
      indent + 'Array',
      getBytes(x, 2),
      n + (n > 1 ? ' elements' : ' element')
    )
    for (let i = 0; i < n; i++) {
      parseDlmsData(ctx, x, indent + ' ')
    }
  } else if (choice === 2) {
    const n = x.input[x.index + 1]
    putBytes(ctx, indent + 'Structure', getBytes(x, 2))
    for (let i = 0; i < n; i++) {
      parseDlmsData(ctx, x, indent + ' ')
    }
  } else if (choice === 3) {
    parseDlmsBoolean(ctx, x, indent + 'Boolean', true)
  } else if (choice === 4) {
    parseDlmsBitString(ctx, x, indent + 'Bit String', true)
  } else if (choice === 5) {
    parseDlmsDoubleLong(ctx, x, indent + 'Double Long', true)
  } else if (choice === 6) {
    parseDlmsDoubleLongUnsigned(ctx, x, indent + 'Double Long Unsigned', true)
  } else if (choice === 9) {
    parseDlmsOctetString(ctx, x, indent + 'Octet String', true)
  } else if (choice === 10) {
    parseDlmsOctetString(ctx, x, indent + 'Visible String', true)
  } else if (choice === 15) {
    parseDlmsInteger(ctx, x, indent + 'Integer', true)
  } else if (choice === 16) {
    parseDlmsLong(ctx, x, indent + 'Long', true)
  } else if (choice === 17) {
    parseDlmsUnsigned(ctx, x, indent + 'Unsigned', true)
  } else if (choice === 18) {
    parseDlmsLongUnsigned(ctx, x, indent + 'Long Unsigned', true)
  } else if (choice === 19) {
    parseDlmsCompactArray(ctx, x, indent + 'Compact Array', indent)
  } else if (choice === 22) {
    parseDlmsEnum(ctx, x, indent + 'Enum', true)
  } else {
    throw 'TODO: DLMS Data CHOICE ' + choice
  }
}

function parseDlmsBitString(
  ctx: Context,
  x: Slice,
  name: string,
  hasTag: boolean
) {
  const offset = hasTag ? 1 : 0
  let bitlen = x.input[x.index + offset]
  let bytelen = 1
  if (bitlen === 0x81) {
    bitlen = parseNumber(x, 1, offset)
    bytelen += 1
  } else if (bitlen === 0x82) {
    bitlen = parseNumber(x, 2, offset)
    bytelen += 2
  }

  bytelen += Math.floor((bitlen + 7) / 8)
  putBytes(ctx, name, getBytes(x, offset + bytelen))
}

function getDlmsDate(x: Slice, offset: number) {
  const year = parseNumber(x, 2, offset)
  const month = x.input[x.index + offset + 2]
  const dayOfMonth = x.input[x.index + offset + 3]
  const dayOfWeek = x.input[x.index + offset + 4]

  //Day
  let hday = ''
  if (dayOfMonth === 0xff) hday = 'Every day'
  else if (dayOfMonth === 0xfd)
    hday = '2nd last ' + daysInWeek[dayOfWeek] + ' of'
  else if (dayOfMonth === 0xfe) hday = 'Last ' + daysInWeek[dayOfWeek] + ' of'
  else if (dayOfMonth > 0 && dayOfMonth < 10) hday = '0' + dayOfMonth
  else if (dayOfMonth > 0 && dayOfMonth <= 31) hday = String(dayOfMonth)
  else return null

  //Month
  let hmon = ''
  if (month === 0xff) hmon = 'every month of'
  else if (month === 0xfd) hmon = 'DST-end month of'
  else if (month === 0xfe) hmon = 'DST-begin month of'
  else if (month >= 1 && month <= 12) hmon = monthsInYear[month]
  else return null

  //Year
  let hyear = ''
  if (year === 0xffff) hyear = 'every year'
  else hyear = String(year)

  const date = hday + ' ' + hmon + ' ' + hyear
  return date
}

function getDlmsTime(x: Slice, offset: number) {
  const hour = x.input[x.index + offset]
  const mins = x.input[x.index + offset + 1]
  const sec = x.input[x.index + offset + 2]
  const hsec = x.input[x.index + offset + 3]

  let xhour = ''
  if (hour === 0xff) xhour = 'Every hour'
  else if (hour < 10) xhour = '0' + hour
  else if (hour > 23) return null

  let xmins = ''
  if (mins === 0xff) xmins = 'Every minute'
  else if (mins < 10) xmins = '0' + mins
  else if (mins > 59) return null

  let xsec = ''
  if (sec === 0xff) xsec = 'Every second'
  else if (sec < 10) xsec = '0' + sec
  else if (sec > 59) return null

  let xhsec = ''
  if (hsec === 0xff) xhsec = '00'
  else if (hsec < 10) xhsec = '0' + hsec

  return `${xhour}:${xmins}:${xsec}.${xhsec}`
}

function getDlmsLongDate(x: Slice, offset: number) {
  function checkSameValue(arr: Uint8Array, val: number) {
    for (let i = 0; i < arr.length; i++) {
      if (arr[i] !== val) return false
    }
    return true
  }

  const dev = parseNumber(x, 2, offset + 9)
  const clk = x.input[x.index + offset + 11]
  if (dev === 0x8000 && clk === 0xff) {
    const dateTimeSlice = x.input.subarray(
      x.index + offset,
      x.index + offset + 9
    )
    if (checkSameValue(dateTimeSlice, 0x00)) {
      // for DLMS COSEM Commands Payloads, activation date-time(s) have the value 0x0000000000000000008000FF;
      return 'NOW'
    } else if (checkSameValue(dateTimeSlice, 0xff)) {
      // for DLMS COSEM Commands Payloads, activation date-time(s) have the value 0xFFFFFFFFFFFFFFFFFF8000FF;
      return 'NEVER'
    }
  }

  let date = getDlmsDate(x, offset)
  const time = getDlmsTime(x, offset + 5)
  if (date && time) date += ' ' + time
  return date
}

function getDlmsObis(x: Slice, offset: number) {
  x.index += offset
  const text = formatObis(x)
  x.index -= offset
  return text
}

export function parseDlmsOctetString(
  ctx: Context,
  x: Slice,
  name: string,
  hasTag: boolean
) {
  const offset = hasTag ? 1 : 0
  const lenSz = parseLength(x, offset)
  const len = lenSz.length
  let stringLike = true
  for (let i = 0; i < len; i++) {
    const c = x.input[x.index + offset + lenSz.size + i]
    if (c < 0x20 || c > 0x7e) {
      stringLike = false
      break
    }
  }
  let text: string | null = ''
  if (len > 1 && stringLike) {
    for (let i = 0; i < len; i++) {
      text += String.fromCharCode(x.input[x.index + offset + lenSz.size + i])
    }
    text = '"' + text + '"'
  } else if (len === 4) {
    text = getDlmsTime(x, offset + 1)
  } else if (len === 5) {
    text = getDlmsDate(x, offset + 1)
  } else if (len === 12) {
    text = getDlmsLongDate(x, offset + 1)
  } else if (len === 6) {
    text = getDlmsObis(x, offset + 1)
  }
  putBytes(ctx, name, getBytes(x, offset + lenSz.size + len), text ?? undefined)
}

function parseDlmsBoolean(
  ctx: Context,
  x: Slice,
  name: string,
  hasTag: boolean
) {
  const offset = hasTag ? 1 : 0
  const value = x.input[x.index + offset] ? 'True' : 'False'
  putBytes(ctx, name, getBytes(x, offset + 1), value)
}

function parseDlmsNumber(
  ctx: Context,
  x: Slice,
  name: string,
  size: number,
  hasTag: boolean,
  hasSign: boolean
) {
  const offset = hasTag ? 1 : 0
  let value = parseNumber(x, size, offset)
  if (hasSign && value > Math.abs(1 << (size * 8 - 1)) - 1) {
    value -= 1 << (size * 8)
  }
  //value = tooltip(value, toHex(value, size * 8))
  putBytes(ctx, name, getBytes(x, offset + size), String(value))
}

function parseDlmsInteger(
  ctx: Context,
  x: Slice,
  name: string,
  hasTag: boolean
) {
  parseDlmsNumber(ctx, x, name, 1, hasTag, true)
}

function parseDlmsUnsigned(
  ctx: Context,
  x: Slice,
  name: string,
  hasTag: boolean
) {
  parseDlmsNumber(ctx, x, name, 1, hasTag, false)
}

function parseDlmsLong(ctx: Context, x: Slice, name: string, hasTag: boolean) {
  parseDlmsNumber(ctx, x, name, 2, hasTag, true)
}

function parseDlmsLongUnsigned(
  ctx: Context,
  x: Slice,
  name: string,
  hasTag: boolean
) {
  parseDlmsNumber(ctx, x, name, 2, hasTag, false)
}

function parseDlmsDoubleLong(
  ctx: Context,
  x: Slice,
  name: string,
  hasTag: boolean
) {
  parseDlmsNumber(ctx, x, name, 4, hasTag, true)
}

function parseDlmsDoubleLongUnsigned(
  ctx: Context,
  x: Slice,
  name: string,
  hasTag: boolean
) {
  parseDlmsNumber(ctx, x, name, 4, hasTag, false)
}

function parseDlmsEnum(
  ctx: Context,
  x: Slice,
  name: string,
  hasTag: boolean,
  values?: Record<number, string>
) {
  const offset = hasTag ? 1 : 0
  const value = parseNumber(x, 1, offset)
  const notes = (values && values[value]) || String(value)
  putBytes(ctx, name, getBytes(x, offset + 1), notes)
}

function parseDlmsAlertCode(ctx: Context, x: Slice) {
  const alertCode = parseNumber(x, 2, 1)
  putBytes(ctx, 'Alert Code', getBytes(x, 3), getAlertCodeName(alertCode))
}

function parseDlmsCompactArray(
  ctx: Context,
  x: Slice,
  name: string,
  indent?: string
) {
  indent = indent ?? ''
  putBytes(ctx, name, getBytes(x, 1))
  putBytes(ctx, indent + ' Type Description', getBytes(x, 0))
  const typeDescription = parseDlmsTypeDescription(ctx, x, indent + '  ')
  parseDlmsCompactArrayContents(ctx, indent + ' ', x, typeDescription)
}

type DlmsTypeDescription =
  | {
      choice: 1 /* array */
      children: { number: number; type: DlmsTypeDescription }
    }
  | {
      choice: 2 /* structure */
      children: DlmsTypeDescription[]
    }
  | {
      choice: 3 | 4 | 5 | 6 | 9 | 10 | 15 | 16 | 17 | 18 | 22
    }

function parseDlmsTypeDescription(
  ctx: Context,
  x: Slice,
  indent?: string
): DlmsTypeDescription {
  const choice = x.input[x.index]
  if (choice === 1) {
    // array
    const numberOfElements = parseNumber(x, 2, 1)
    putBytes(ctx, indent + 'Array of ' + numberOfElements, getBytes(x, 3))
    const t = parseDlmsTypeDescription(ctx, x, indent + ' ')
    return { choice, children: { number: numberOfElements, type: t } }
  } else if (choice === 2) {
    // structure
    const n = x.input[x.index + 1]
    putBytes(ctx, indent + 'Structure', getBytes(x, 2))
    const typeDescription: DlmsTypeDescription = { choice, children: [] }
    for (let i = 0; i < n; i++) {
      const t = parseDlmsTypeDescription(ctx, x, indent + ' ')
      typeDescription.children.push(t)
    }
    return typeDescription
  } else if (choice === 3) {
    // boolean
    putBytes(ctx, indent + 'Boolean', getBytes(x, 1))
    return { choice }
  } else if (choice === 4) {
    // bit-string
    putBytes(ctx, indent + 'Bit-String', getBytes(x, 1))
    return { choice }
  } else if (choice === 5) {
    // double-long
    putBytes(ctx, indent + 'Double Long', getBytes(x, 1))
    return { choice }
  } else if (choice === 6) {
    // double-long-unsigned
    putBytes(ctx, indent + 'Double Long Unsigned', getBytes(x, 1))
    return { choice }
  } else if (choice === 9) {
    // octet-string
    putBytes(ctx, indent + 'Octet String', getBytes(x, 1))
    return { choice }
  } else if (choice === 10) {
    // visible-string
    putBytes(ctx, indent + 'Visible String', getBytes(x, 1))
    return { choice }
  } else if (choice === 15) {
    // integer
    putBytes(ctx, indent + 'Integer', getBytes(x, 1))
    return { choice }
  } else if (choice === 16) {
    // long
    putBytes(ctx, indent + 'Long', getBytes(x, 1))
    return { choice }
  } else if (choice === 17) {
    // unsigned
    putBytes(ctx, indent + 'Unsigned', getBytes(x, 1))
    return { choice }
  } else if (choice === 18) {
    // long-unsigned
    putBytes(ctx, indent + 'Long Unsigned', getBytes(x, 1))
    return { choice }
  } else if (choice === 22) {
    // enum
    putBytes(ctx, indent + 'Enum', getBytes(x, 1))
    return { choice }
  } else {
    throw new Error(`unknown dlms type: ${choice}`)
  }
}

function parseDlmsCompactArrayContents(
  ctx: Context,
  indent: string,
  x: Slice,
  typeDescription: DlmsTypeDescription
) {
  const lenSz = parseLength(x)
  const arrayContentsLen = lenSz.length
  const bytes = lenSz.size
  putBytes(ctx, indent + 'Contents', getBytes(x, bytes))
  const contents = getBytes(x, arrayContentsLen)
  let index = 0
  while (contents.index < contents.end) {
    // put each element of the array according to the type description
    parseDlmsTypeDescriptionContentsData(
      ctx,
      indent + '[' + index + '] ',
      contents,
      typeDescription
    )
    index++
  }
}

function parseDlmsTypeDescriptionContentsData(
  ctx: Context,
  indent: string,
  x: Slice,
  typeDescription: DlmsTypeDescription
) {
  const choice = typeDescription.choice
  if (choice === 1) {
    // array
    const n = typeDescription.children.number
    const t = typeDescription.children.type
    putBytes(ctx, indent + 'Array', getBytes(x, 0), n + ' elements')
    for (let i = 0; i < n; i++) {
      parseDlmsTypeDescriptionContentsData(ctx, indent + ' ', x, t)
    }
  } else if (choice === 2) {
    // structure
    const n = typeDescription.children.length
    putBytes(ctx, indent + 'Structure', getBytes(x, 0))
    for (let i = 0; i < n; i++) {
      const t = typeDescription.children[i]
      parseDlmsTypeDescriptionContentsData(ctx, indent + ' ', x, t)
    }
  } else if (choice === 3) {
    // boolean
    parseDlmsBoolean(ctx, x, indent + 'Boolean', false)
  } else if (choice === 4) {
    // bit-string
    parseDlmsBitString(ctx, x, indent + 'Bit String', false)
  } else if (choice === 5) {
    // double-long
    parseDlmsDoubleLong(ctx, x, indent + 'Double Long', false)
  } else if (choice === 6) {
    // double-long-unsigned
    parseDlmsDoubleLongUnsigned(ctx, x, indent + 'Double Long Unsigned', false)
  } else if (choice === 9) {
    // octet-string
    parseDlmsOctetString(ctx, x, indent + 'Octet String', false)
  } else if (choice === 10) {
    // visible-string
    parseDlmsOctetString(ctx, x, indent + 'Visible String', false)
  } else if (choice === 15) {
    // integer
    parseDlmsInteger(ctx, x, indent + 'Integer', false)
  } else if (choice === 16) {
    // long
    parseDlmsLong(ctx, x, indent + 'Long', false)
  } else if (choice === 17) {
    // unsigned
    parseDlmsUnsigned(ctx, x, indent + 'Unsigned', false)
  } else if (choice === 18) {
    // long-unsigned
    parseDlmsLongUnsigned(ctx, x, indent + 'Long Unsigned', false)
  } else if (choice === 22) {
    // enum
    parseDlmsEnum(ctx, x, indent + 'Enum', false)
  } else {
    throw new Error('TODO: DLMS Data CHOICE (compact array)' + choice)
  }
}

function parseDlmsCosemAttributeDescriptor(ctx: Context, x: Slice) {
  const cosemClass = parseDlmsCosemClassId(ctx, x)
  parseDlmsCosemInstanceId(ctx, x, cosemClass)
  parseDlmsCosemAttributeId(ctx, x, cosemClass)
}

function parseDlmsCosemMethodDescriptor(ctx: Context, x: Slice) {
  const cosemClass = parseDlmsCosemClassId(ctx, x)
  parseDlmsCosemInstanceId(ctx, x, cosemClass)
  parseDlmsCosemMethodId(ctx, x, cosemClass)
}

function parseDlmsCosemClassId(ctx: Context, x: Slice) {
  // The attributes arrays start with attribute 2 (attribute 1 is always "logical_name").
  // The methods arrays start with method 1.
  const classes: Record<number, CosemClass> = {
    0x0001: {
      name: 'Data',
      attributes: ['Value'],
      methods: [],
      instances: {
        0x00005e2c0301: 'Disable Privacy PIN Protection',
        0x00005e2c0302: 'Restrict Data Date Time',
        0x00005e2c0a00: 'Sub GHz Configuration Settings',
        0x00005e2c0a01: 'CHF Sub GHz Channel Scan',
        0x00005e2c0a02: 'Operating Sub GHz Channel',
        0x00005e2c2214: 'Power Import Collection',
        0x0002600d01ff: 'Supplier Message',
      },
    },
    0x0003: {
      name: 'Register',
      attributes: ['Value', 'Scaler Unit'],
      methods: [],
      instances: {
        0x0100020800ff: 'Active Export Register',
        0x0100040800ff: 'Reactive Export Register',
      },
    },
    0x0007: {
      name: 'Profile Generic',
      attributes: [],
      methods: ['Reset'],
      instances: {
        0x0000636200ff: 'Event Log (inc GPF)',
        0x0011636202ff: 'Auxiliary Load Control Switch Event Log',
      },
    },
    0x0009: {
      name: 'Script Table',
      attributes: [],
      methods: ['Execute'],
      instances: { 0x00000a0064ff: 'Tariff Block Counter Matrix TOU' },
    },
    0x000a: {
      name: 'Schedule',
      attributes: ['Entries'],
      methods: [],
      instances: { 0x00010c0001ff: 'Non-Disablement Calendar' },
    },
    0x000b: {
      name: 'Special Days Table',
      attributes: ['Entries'],
      methods: [],
      instances: {
        0x00010b0000ff: 'Tariff Switching Table Special Days',
        0x00010b0001ff: 'Tariff Switching Table Secondary Element Special Days',
        0x00010b0002ff: 'Non-Disablement Calendar Special Days',
      },
    },
    0x0014: {
      name: 'Activity Calendar',
      attributes: [
        'Calendar Name Active',
        'Season Profile Active',
        'Week Profile Table Active',
        'Day Profile Table Active',
        'Calendar Name Passive',
        'Season Profile Passive',
        'Week Profile Table Passive',
        'Day Profile Table Passive',
        'Activate Passive Calendar Time',
      ],
      methods: [],
      instances: {
        0x00000d0000ff: 'Tariff Switching Table',
        0x00000d0001ff: 'Tariff Switching Table Secondary Element',
      },
    },
    0x0015: {
      name: 'Register Monitor',
      attributes: ['Thresholds'],
      methods: [],
      instances: {
        0x000010010bff: 'Tariff Threshold Matrix Blocks TOU1',
        0x000010010cff: 'Tariff Threshold Matrix Blocks TOU2',
        0x000010010dff: 'Tariff Threshold Matrix Blocks TOU3',
        0x000010010eff: 'Tariff Threshold Matrix Blocks TOU4',
        0x000010010fff: 'Tariff Threshold Matrix Blocks TOU5',
        0x0000100110ff: 'Tariff Threshold Matrix Blocks TOU6',
        0x0000100111ff: 'Tariff Threshold Matrix Blocks TOU7',
        0x0000100112ff: 'Tariff Threshold Matrix Blocks TOU8',
      },
    },
    0x001e: {
      name: 'Data Protection',
      attributes: [],
      methods: ['Get Protected Attributes'],
      instances: {
        0x00002b0208ff: 'Import Register Collection',
        0x00002b0209ff: 'Tariff TOU Register Collection',
        0x00002b020aff: 'Tariff Block TOU Register Collection',
      },
    },
    0x0068: {
      name: 'ZigBee Network Control',
      attributes: ['Enable Disable Joining', 'Join Timeout', 'Active Devices'],
      methods: [
        'Register Device',
        'Unregister Device',
        'Unregister All Devices',
        'Backup PAN',
        'Restore PAN',
      ],
      instances: { 0x00001e0300ff: 'Device Log (CHF)' },
    },
    0x006f: {
      name: 'Account',
      attributes: [
        'Account Mode and Status',
        'Current Credit in Use',
        'Current Credit Status',
        'Available Credit',
        'Amount to Clear',
        'Clearance Threshold',
        'Aggregated Debt',
        'Credit Reference List',
        'Charge Reference List',
        'Credit Charge Configuration',
        'Token Gateway Configuration',
        'Account Activation Time',
      ],
      methods: [],
      instances: {
        0x0001130000ff:
          'SuspendDebtDisabled / SuspendDebtEmergency / Payment Mode',
      },
    },
    0x0070: {
      name: 'Credit',
      attributes: [],
      methods: ['Update Amount', 'Set Amount to Value', 'Invoke Credit'],
      instances: {
        0x0000130a00ff: 'Meter Balance',
        0x0000130a01ff: 'Emergency Credit Balance',
        0x0000130a02ff: 'Accumulated Debt Register',
      },
    },
    0x0071: {
      name: 'Charge',
      attributes: [
        'Total Amount Paid',
        'Charge Type',
        'Priority',
        'Unit Charge Active',
        'Unit Charge Passive',
        'Unit Charge Activation Time',
        'Period',
        'Charge Configuration',
        'Last Collection Time',
        'Last Collection Amount',
        'Total Amount Remaining',
        'Proportion',
      ],
      methods: [
        'Update Unit Charge',
        'Activate Passive Unit Charge',
        'Collect',
        'Update Total Amount Remaining',
      ],
      instances: {
        0x0000131400ff: 'Tariff Block Price Matrix TOU',
        0x0000131401ff: 'Debt Recovery Rates 1',
        0x0000131402ff: 'Debt Recovery Rates 2',
        0x0000131403ff: 'Debt Recovery per Payment',
        0x0000131404ff: 'Standing Charge',
        0x0000131405ff: 'Secondary Tariff TOU Price Matrix',
      },
    },
    0x0073: {
      name: 'Token Gateway',
      attributes: [],
      methods: ['Enter'],
      instances: { 0x0000132800ff: 'Prepayment Credit' },
    },
    0x2328: {
      name: 'GBCS Extended Data',
      attributes: [
        'Value Active',
        'Scaler Unit Active',
        'Value Passive',
        'Scaler Unit Passive',
        'Activate Passive Value Time',
      ],
      methods: [],
      instances: {
        0x00003f0101ff: 'Tariff Threshold Matrix',
        0x00005e2c0200: 'Currency Unit',
        0x00005e2c020a: 'Prepayment Credit Max Credit Threshold',
        0x00005e2c0214: 'Prepayment Credit Max Meter Balance',
        0x00005e2c8003: 'Emergency Credit Threshold',
        0x00005e2c8009: 'Low Credit Threshold',
        0x00005e2c800c: 'Debt Recovery Rate Cap Amount',
        0x00005e2c8002: 'Emergency Credit Limit',
        0x00005e2c800d: 'Debt Recovery Rate Cap Period',
        0x00005e2c8016: 'Disablement Threshold Meter Balance',
        0x00005e2c801c: 'Non-Disablement Calendar',
        0x00005e2c801d: 'Tariff Switching Table Special Days',
        0x00005e2c801e: 'Tariff Switching Table Secondary Element Special Days',
        0x00005e2c801f: 'Non-Disablement Calendar Special Days',
        0x0000600d00ff: 'Contact Details Supplier Telephone Number',
        0x0000600d01ff: 'Contact Detail Supplier Name',
      },
    },
  }
  const id = parseNumber(x, 2)
  const cosemClass = classes[id] || {
    name: 'IC ' + id,
    attributes: [],
    methods: [],
    instances: {},
  }
  putBytes(ctx, ' ┌ Class Id', getBytes(x, 2), '┌ ' + cosemClass.name)
  return cosemClass
}

function formatObis(x: Slice) {
  return (
    x.input[x.index] +
    '-' +
    x.input[x.index + 1] +
    ':' +
    x.input[x.index + 2] +
    '.' +
    x.input[x.index + 3] +
    '.' +
    x.input[x.index + 4] +
    '.' +
    x.input[x.index + 5]
  )
}

function parseDlmsCosemInstanceId(
  ctx: Context,
  x: Slice,
  cosemClass: CosemClass
) {
  const id = parseNumber(x, 6)
  const cosemInstance = cosemClass.instances[id]
  let name = formatObis(x)
  if (cosemInstance !== undefined) name = name + ' - ' + cosemInstance
  putBytes(ctx, ' ├ Instance Id', getBytes(x, 6), '├ ' + name)
}

function parseDlmsCosemAttributeId(
  ctx: Context,
  x: Slice,
  cosemClass: CosemClass
) {
  const id = x.input[x.index]
  const name = cosemClass.attributes[id - 2] || 'Attribute ' + id
  putBytes(ctx, ' └ Attribute Id', getBytes(x, 1), '└ ' + name)
}

function parseDlmsCosemMethodId(
  ctx: Context,
  x: Slice,
  cosemClass: CosemClass
) {
  const id = x.input[x.index]
  const name = cosemClass.methods[id - 1] || 'Method ' + id
  putBytes(ctx, ' └ Method Id', getBytes(x, 1), '└ ' + name)
}

function parseDlmsSelectiveAccessDescriptor(ctx: Context, x: Slice) {
  putBytes(ctx, 'Access Selector', getBytes(x, 1))
  parseDlmsData(ctx, x)
}

function parseDlmsDataAccessResult(ctx: Context, x: Slice) {
  const values: Record<number, string> = {
    0: 'Success',
    1: 'Hardware Fault',
    2: 'Temporary Failure',
    3: 'Read Write Denied',
    4: 'Object Undefined',
    9: 'Object Class Inconsistent',
    11: 'Object Unavailable',
    12: 'Type Unmatched',
    13: 'Scope of Access Violated',
    14: 'Data Block Unavailable',
    15: 'Long Get Aborted',
    16: 'No Long Get in Progress',
    17: 'Long Set Aborted',
    18: 'No Long Set in Progress',
    19: 'Data Block Number Invalid',
    250: 'Other Reason',
  }
  const value = x.input[x.index]
  putBytes(ctx, 'Data Access Result', getBytes(x, 1), values[value] || '')
}

function parseDlmsActionResult(ctx: Context, x: Slice) {
  const values: Record<number, string> = {
    0: 'Success',
    1: 'Hardware Fault',
    2: 'Temporary Failure',
    3: 'Read Write Denied',
    4: 'Object Undefined',
    9: 'Object Class Inconsistent',
    11: 'Object Unavailable',
    12: 'Type Unmatched',
    13: 'Scope of Access Violated',
    14: 'Data Block Unavailable',
    15: 'Long Action Aborted',
    16: 'No Long Action in Progress',
    250: 'Other Reason',
  }
  const value = x.input[x.index]
  putBytes(ctx, 'Action Result', getBytes(x, 1), values[value] || '')
}

// Alert 8F84

export function parseRemotePartyMessage(ctx: Context, x: Slice) {
  const s = parseSequence(ctx, x, 'Remote Party Message')
  putBytes(ctx, 'Business Originator ID', getBytes(s, 8))
  putBytes(ctx, 'Business Target ID', getBytes(s, 8))
  parseCraFlag(ctx, s)
  parseCounter(ctx, 'Originator Counter', s)
}

export function parseFailureToDeliverRemotePartyToEsme(ctx: Context, x: Slice) {
  // Failure to Deliver Remote Party Message to ESME Alert
  putBytes(ctx, 'DLMS Data Notification', getBytes(x, 8))
  parseDlmsAlertCode(ctx, x)
  parseDlmsOctetString(ctx, x, 'Time Stamp', true)
  parseRemotePartyMessage(ctx, x)
}
