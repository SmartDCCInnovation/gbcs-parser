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

import {
  parseCounter,
  parseMessageCode,
  parseMeterIntegrityIssueWarning,
  parseNumber,
  parseNumberLE,
} from './common'
import { Context, putBytes, putSeparator, putUnparsedBytes } from './context'
import { decryptGbcsData } from './crypto'
import { parseDlmsOctetString } from './dlms'
import {
  daysInWeek,
  getAlertCodeName,
  getBytes,
  monthsInYear,
  Slice,
  toHex,
} from './util'

// GBZ Payloads

export function parseGbzPayload(ctx: Context, x: Slice) {
  putBytes(ctx, 'Profile ID', getBytes(x, 2))
  const numberOfGbzComponents = x.input.byte(x.index)
  putBytes(
    ctx,
    'Number of GBZ components',
    getBytes(x, 1),
    String(numberOfGbzComponents),
  )
  for (let i = 1; i <= numberOfGbzComponents; i++) {
    putSeparator(ctx, 'GBZ Component ' + i)
    parseGbzComponent(ctx, x)
  }
}

export function parseGbzAlertPayload(ctx: Context, x: Slice) {
  putBytes(ctx, 'Profile ID', getBytes(x, 2))
  putBytes(ctx, 'Number of GBZ components', getBytes(x, 1))
  parseGbzAlertCode(ctx, x)
  parseGbzTime(ctx, x, 'Time Stamp')
  if (x.index < x.end) {
    putBytes(ctx, 'GBZ Use Case Specific Components', x)
  }
}

export function parseGbzMeterIntegrityIssueWarningAlert(
  ctx: Context,
  x: Slice,
) {
  putBytes(ctx, 'Profile ID', getBytes(x, 2))
  putBytes(ctx, 'Number of GBZ components', getBytes(x, 1))
  parseGbzAlertCode(ctx, x)
  parseGbzTime(ctx, x, 'Time Stamp')
  putBytes(ctx, 'GBZ Use Case Specific Components', getBytes(x, 0))
  parseMeterIntegrityIssueWarning(ctx, x, ' ')
}

export function parseGbzFutureDatedAlertPayload(ctx: Context, x: Slice) {
  putBytes(ctx, 'Profile ID', getBytes(x, 2))
  putBytes(ctx, 'Number of GBZ components', getBytes(x, 1))
  parseGbzAlertCode(ctx, x)
  parseGbzTime(ctx, x, 'Time Stamp')
  putBytes(ctx, 'Future Dated Alert Payload', getBytes(x, 1))
  parseMessageCode(ctx, 'Message Code', x)
  parseCounter(ctx, 'Originator Counter', x)
  const cluster = parseClusterId(ctx, x)
  const frameControl = x.input.byte(x.index)
  putBytes(ctx, 'Frame Control', getBytes(x, 1))
  parseCommandId(ctx, x, '', frameControl, cluster)
}

export function parseGbzFirmwareDistributionReceiptAlert(
  ctx: Context,
  x: Slice,
) {
  putBytes(ctx, 'Profile ID', getBytes(x, 2))
  putBytes(ctx, 'Number of GBZ components', getBytes(x, 1))
  parseGbzAlertCode(ctx, x)
  parseGbzTime(ctx, x, 'Time Stamp')
  parseDlmsOctetString(ctx, x, 'Calculated Manufacturer Hash', true)
}

export function parseGbzGcs53AlertPayload(ctx: Context, x: Slice) {
  putBytes(ctx, 'Profile ID', getBytes(x, 2))
  putBytes(ctx, 'Number of GBZ components', getBytes(x, 1))
  parseGbzAlertCode(ctx, x)
  parseGbzTime(ctx, x, 'Time Stamp')
  parseGbzComponent(ctx, x)
}

function parseGbzAlertCode(ctx: Context, x: Slice) {
  const alertCode = parseNumber(x, 2)
  putBytes(ctx, 'Alert Code', getBytes(x, 2), getAlertCodeName(alertCode))
}

function parseGbzComponent(ctx: Context, x: Slice) {
  const controlField = x.input.byte(x.index)
  if (controlField & 0x02) {
    putBytes(ctx, 'Control Field', getBytes(x, 1)) //, swapped)
  } else {
    putBytes(ctx, 'Control Field', getBytes(x, 1))
  }
  const cluster = parseClusterId(ctx, x)
  // Extended Header GBZ Command Length
  const extendedLen = parseNumber(x, 2)
  putBytes(ctx, 'Length', getBytes(x, 2), String(extendedLen))
  const y = getBytes(x, extendedLen)
  if (controlField & 0x02) {
    // encrypted content
    putBytes(ctx, 'Additional Header Control', getBytes(y, 1))
    putBytes(ctx, 'Additional Header Frame Counter', getBytes(y, 1))
  } else if (controlField & 0x10) {
    parseGbzTime(ctx, y, 'From Date Time')
  }
  // ZCL Header
  const frameControl = y.input.byte(y.index)
  putBytes(ctx, 'ZCL Header', getBytes(y, 0))
  putBytes(ctx, ' Frame Control', getBytes(y, 1))
  putBytes(ctx, ' Sequence Number', getBytes(y, 1))
  const command = parseCommandId(ctx, y, ' ', frameControl, cluster)
  if (controlField & 0x02) {
    // encrypted payload
    const len = parseNumber(y, 2)
    putBytes(ctx, 'Ciphered Information Length', getBytes(y, 2), String(len))
    putBytes(ctx, 'Security Header', getBytes(y, 5))
    const ciphertextAndTag = y.input.buffer.subarray(y.index, y.index + len - 5)
    putBytes(ctx, 'Encrypted ZCL Payload', getBytes(y, len - 5 - 12))
    putBytes(ctx, 'AE MAC', getBytes(y, 12))

    decryptGbcsData(ctx, ciphertextAndTag, function (yy) {
      if (command && command.parse) {
        putBytes(ctx, 'ZCL Payload', getBytes(x, 0), command.name)
        command.parse({ ctx, x: yy, cluster, frameControl, indent: ' ' })
      } else {
        putBytes(ctx, 'ZCL Payload', yy)
      }
      putUnparsedBytes(yy)
    })
  } else {
    // plaintext payload
    if (command && command.parse) {
      putBytes(ctx, 'ZCL Payload', getBytes(x, 0), command.name)
      command.parse({ ctx, x: y, cluster, frameControl, indent: ' ' })
    } else {
      putBytes(ctx, 'ZCL Payload', y)
    }
    putUnparsedBytes(y)
  }
}

interface ZclParseOptions {
  ctx: Context
  x: Slice
  cluster: ZclCluster
  frameControl: number
  indent: string
}
type ZclParse = (options: ZclParseOptions) => void

interface ZclCluster {
  name: string
  attributes: Record<number, string>
  commands: Record<number, [string, ZclParse]>
  responses: Record<number, [string, ZclParse]>
}

function parseClusterId(ctx: Context, x: Slice) {
  const clusters: Record<number, ZclCluster> = {
    0x0000: {
      name: 'Basic',
      attributes: {
        0x0003: 'HW Version',
        0x0004: 'Manufacturer Name',
        0x0005: 'Model Identifier',
      },
      commands: {},
      responses: {},
    },
    0x0700: {
      name: 'Price',
      attributes: {
        0x0100: 'Block 1 Threshold',
        0x0101: 'Block 2 Threshold',
        0x0102: 'Block 3 Threshold',
        0x0202: 'Threshold Multiplier',
        0x0203: 'Threshold Divisor',
        0x0301: 'Standing Charge',
        0x0302: 'Conversion Factor',
        0x0303: 'Conversion Factor Trailing Digit',
        0x0304: 'Calorific Value',
        0x0305: 'Calorific Value Unit',
        0x0306: 'Calorific Value Trailing Digit',
        0x0400: 'No Tier Block 1 Price',
        0x0401: 'No Tier Block 2 Price',
        0x0402: 'No Tier Block 3 Price',
        0x0403: 'No Tier Block 4 Price',
        0x0410: 'Tier 1 Block 1 Price',
        0x0420: 'Tier 2 Block 1 Price',
        0x0430: 'Tier 3 Block 1 Price',
        0x0440: 'Tier 4 Block 1 Price',
        0x0615: 'Unit of Measure',
        0x0616: 'Currency',
        0x0617: 'Price Trailing Digits',
      },
      commands: {
        0: ['Get Current Price', parseZseGetCurrentPrice],
        11: ['Get Billing Period', parseZseGetBillingPeriod],
      },
      responses: {
        0: ['Publish Price', parseZsePublishPrice],
        1: ['Publish Block Period', parseZsePublishBlockPeriod],
        2: ['Publish Conversion Factor', parseZsePublishConversionFactor],
        3: ['Publish Calorific Value', parseZsePublishCalorificValue],
        4: ['Publish Tariff Information', parseZsePublishTariffInformation],
        5: ['Publish Price Matrix', parseZsePublishPriceMatrix],
        6: ['Publish Block Thresholds', parseZsePublishBlockThresholds],
        9: ['Publish Billing Period', parseZsePublishBillingPeriod],
      },
    },
    0x0702: {
      name: 'Metering',
      attributes: {
        0x0000: 'Current Summation Delivered',
        0x0014: 'Supply Status',
        0x0100: 'Current Tier 1 Summation Delivered',
        0x0102: 'Current Tier 2 Summation Delivered',
        0x0104: 'Current Tier 3 Summation Delivered',
        0x0106: 'Current Tier 4 Summation Delivered',
        0x0205: 'Remaining Battery Life in Days',
        0x0206: 'Current Meter Id',
        0x0300: 'Unit of Measure',
        0x0301: 'Multiplier',
        0x0302: 'Divisor',
        0x0307: 'Site ID',
        0x0607: 'Supply Tamper State',
        0x0608: 'SupplyDepletionState',
        0x0700: 'Current no Tier Block 1 Summation Delivered',
        0x0701: 'Current no Tier Block 2 Summation Delivered',
        0x0702: 'Current no Tier Block 3 Summation Delivered',
        0x0703: 'Current no Tier Block 4 Summation Delivered',
        0x0a00: 'Bill to Date Delivered',
        0x0b10: 'Uncontrolled Flow Threshold',
        0x0b11: 'Uncontrolled Flow Threshold Unit of Measure',
        0x0b12: 'Uncontrolled Flow Multiplier',
        0x0b13: 'Uncontrolled Flow Divisor',
        0x0b14: 'Flow Stabilisation Period',
        0x0b15: 'Flow Measurement Period',
      },
      commands: {
        6: ['Get Snapshot', parseZseGetSnapshot],
        7: ['Start Sampling', parseZseStartSampling],
        8: ['Get Sampled Data', parseZseGetSampledData],
        11: ['Change Supply', parseZseChangeSupply],
        13: ['Set Supply Status', parseZseSetSupplyStatus],
        14: [
          'Set Uncontrolled Flow Threshold',
          parseZseSetUncontrolledFlowThreshold,
        ],
      },
      responses: {
        6: ['Publish Snapshot', parseZsePublishSnapshot],
        7: ['Get Sampled Data Response', parseZseGetSampledDataResponse],
        12: ['Supply Status Response', parseZseSupplyStatusResponse],
        13: ['Start Sampling Response', parseZseStartSamplingResponse],
      },
    },
    0x0703: {
      name: 'Messaging',
      attributes: {},
      commands: {},
      responses: {
        0: ['Display Message', parseZseDisplayMessage],
      },
    },
    0x0705: {
      name: 'Prepayment',
      attributes: {
        0x0000: 'Payment Control Configuration',
        0x0001: 'Credit Remaining',
        0x0002: 'Emergency Credit Remaining',
        0x0005: 'Accumulated Debt',
        0x0006: 'Overall Debt Cap',
        0x0010: 'Emergency Credit Limit',
        0x0011: 'Emergency Credit Threshold',
        0x0021: 'Max Credit Limit',
        0x0022: 'Max Credit Per Top Up',
        0x0031: 'Low Credit Warning Level',
        0x0040: 'Cut Off Value',
        0x0211: 'Debt Amount 1 (Time-Based Debt 1)',
        0x0216: 'Debt Recovery Frequency 1',
        0x0217: 'Debt Recovery Amount 1',
        0x0221: 'Debt Amount 2 (Time-Based Debt 2)',
        0x0226: 'Debt Recovery Frequency 2',
        0x0227: 'Debt Recovery Amount 2',
        0x0231: 'Debt Amount 3 (Payment-Based Debt)',
        0x0239: 'Debt Recovery Top Up Percentage 3',
      },
      commands: {
        0: [
          'Select Available Emergency Credit',
          parseZseSelectAvailableEmergencyCredit,
        ],
        2: ['Change Debt', parseZseChangeDebt],
        3: ['Emergency Credit Setup', parseZseEmergencyCreditSetup],
        4: ['Consumer Top Up', parseZseConsumerTopUp],
        5: ['Credit Adjustment', parseZseCreditAdjustment],
        6: ['Change Payment Mode', parseZseChangePaymentMode],
        7: ['Get Prepay Snapshot', parseZseGetPrepaySnapshot],
        8: ['Get Top Up Log', parseZseGetTopUpLog],
        9: ['Set Low Credit Warning Level', parseZseSetLowCreditWarningLevel],
        10: ['Get Debt Repayment Log', parseZseGetDebtRepaymentLog],
        11: ['Set Maximum Credit Limit', parseZseSetMaximumCreditLimit],
        12: ['Set Overall Debt Cap', parseZseSetOverallDebtCap],
      },
      responses: {
        1: ['Publish Prepay Snapshot', parseZsePublishPrepaySnapshot], // encrypted payload
        2: ['Change Payment Mode Response', parseZseChangePaymentModeResponse],
        3: ['Consumer Top Up Response', parseZseConsumerTopUpResponse],
        5: ['Publish Top Up Log', parseZsePublishTopUpLog],
        6: ['Publish Debt Log', parseZsePublishDebtLog],
      },
    },
    0x0707: {
      name: 'Calendar',
      attributes: {},
      commands: {
        0: ['Get Calendar', parseZclNoop],
        1: ['Get Day Profiles', parseZseGetDayProfiles],
        2: ['Get Week Profiles', parseZseGetWeekProfiles],
        3: ['Get Seasons', parseZseGetSeasons],
        4: ['Get Special Days', parseZseGetSpecialDays],
      },
      responses: {
        0: ['Publish Calendar', parseZsePublishCalendar],
        1: ['Publish Day Profile', parseZsePublishDayProfile],
        2: ['Publish Week Profile', parseZsePublishWeekProfile],
        3: ['Publish Seasons', parseZsePublishSeasons],
        4: ['Publish Special Days', parseZsePublishSpecialDays],
      },
    },
    0x0708: {
      name: 'Device Management',
      attributes: {},
      commands: {
        4: ['Report Event Configuration', parseZseReportEventConfiguration],
      },
      responses: {
        0: ['Publish Change of Tenancy', parseZsePublishChangeOfTenancy],
        1: ['Publish Change of Supplier', parseZsePublishChangeOfSupplier],
        2: [
          'Request New Password Response',
          parseZseRequestNewPasswordResponse,
        ],
        3: ['Update Site Id', parseZseUpdateSiteId],
        4: ['Set Event Configuration', parseZseSetEventConfiguration],
        5: ['Get Event Configuration', parseZseGetEventConfiguration],
        6: ['Update CIN', parseZseUpdateCin],
      },
    },
    0x0709: {
      name: 'Events',
      attributes: {},
      commands: {
        0: ['Get Event Log', parseZseGetEventLog],
        1: ['Clear Event Log Request', parseZseClearEventLogRequest],
      },
      responses: {
        1: ['Publish Event Log', parseZsePublishEventLog],
        2: ['Clear Event Log Response', parseZseClearEventLogResponse],
      },
    },
  }
  const clusterId = parseNumber(x, 2)
  const cluster = clusters[clusterId] || {
    name: '',
    attributes: {},
    commands: {},
    responses: {},
  }
  putBytes(ctx, 'Cluster Id', getBytes(x, 2), cluster.name)
  return cluster
}

function parseCommandId(
  ctx: Context,
  x: Slice,
  indent: string,
  frameControl: number,
  cluster: ZclCluster,
) {
  let command: [string, ZclParse] | undefined = undefined
  const commandId = x.input.byte(x.index)
  const frameType = frameControl & 3
  if (frameType === 0) {
    const profileCommands: Record<number, [string, ZclParse]> = {
      0: ['Read Attributes', parseZclReadAttributes],
      1: ['Read Attributes Response', parseZclReadAttributesResponse],
      11: ['Default Response', parseZclDefaultResponse],
    }
    command = profileCommands[commandId as 0 | 1 | 11]
  } else if (frameType === 1) {
    const direction = frameControl & 8
    if (direction === 0) {
      command = cluster.commands[commandId]
    } else {
      command = cluster.responses[commandId]
    }
  }
  if (!command) {
    throw new Error('unable to parse command id')
  }
  const name = command[0]
  putBytes(ctx, `${indent}Command Id`, getBytes(x, 1), name)
  return { name: command[0], parse: command[1] }
}

// ZCL commands

const parseZclNoop: (x: ZclParseOptions) => void = () => undefined

function parseZclReadAttributes({ ctx, x, cluster, indent }: ZclParseOptions) {
  let ctr = 0
  while (x.index < x.end) {
    const id = parseNumberLE(x, 2)
    const name = cluster.attributes[id] || ''
    putBytes(ctx, `${indent}Attribute Id ${ctr}`, getBytes(x, 2), name)
    ctr++
  }
}

function parseZclReadAttributesResponse({
  ctx,
  x,
  cluster,
  indent,
}: ZclParseOptions) {
  for (let i = 1; x.index < x.end; i++) {
    putBytes(ctx, `${indent}Attribute ${i}`, getBytes(x, 0))
    const indent2 = ' ' + indent
    const id = parseNumberLE(x, 2)
    const name = cluster.attributes[id] || ''
    putBytes(ctx, `${indent2}Attribute Id`, getBytes(x, 2), name)
    const status = parseZclStatusCode(ctx, x, indent2)
    if (status === 0) {
      const typeName = `${indent2}Attribute Data Type`
      const valueName = `${indent2}Attribute Data Value`
      const type = x.input.byte(x.index)
      if (type === 0x18) {
        putBytes(ctx, typeName, getBytes(x, 1), `BITMAP8`)
        parseZclBitmap(ctx, 8, x, valueName)
      } else if (type === 0x19) {
        putBytes(ctx, typeName, getBytes(x, 1), `BITMAP16`)
        parseZclBitmap(ctx, 16, x, valueName)
      } else if (type === 0x20) {
        putBytes(ctx, typeName, getBytes(x, 1), `UINT8`)
        parseZclUint(ctx, 8, x, valueName)
      } else if (type === 0x21) {
        putBytes(ctx, typeName, getBytes(x, 1), `UINT16`)
        parseZclUint(ctx, 16, x, valueName)
      } else if (type === 0x22) {
        putBytes(ctx, typeName, getBytes(x, 1), `UINT24`)
        parseZclUint(ctx, 24, x, valueName)
      } else if (type === 0x23) {
        putBytes(ctx, typeName, getBytes(x, 1), `UINT32`)
        parseZclUint(ctx, 32, x, valueName)
      } else if (type === 0x25) {
        putBytes(ctx, typeName, getBytes(x, 1), `UINT48`)
        parseZclUint(ctx, 48, x, valueName)
      } else if (type === 0x2b) {
        putBytes(ctx, typeName, getBytes(x, 1), `INT32`)
        parseZclInt32(ctx, x, valueName)
      } else if (type === 0x30) {
        putBytes(ctx, typeName, getBytes(x, 1), `ENUM8`)
        parseZclEnum(ctx, 8, x, valueName)
      } else if (type === 0x41) {
        putBytes(ctx, typeName, getBytes(x, 1), `Octet String`)
        parseZclOctetString(ctx, x, valueName)
      } else if (type === 0x42) {
        putBytes(ctx, typeName, getBytes(x, 1), `Character String`)
        parseZclOctetString(ctx, x, valueName)
      } else {
        throw 'TODO: Read Attributes Response data type ' + type
      }
    }
  }
}

function parseZclDefaultResponse({
  ctx,
  x,
  cluster,
  frameControl,
  indent,
}: ZclParseOptions) {
  let command: [string, ZclParse] | undefined = undefined
  const commandId = x.input.byte(x.index)
  const direction = frameControl & 8
  if (direction === 0) {
    command = cluster.responses[commandId]
  } else {
    command = cluster.commands[commandId]
  }
  const name = (command && command[0]) || ''
  putBytes(ctx, `${indent}Command Id`, getBytes(x, 1), name)
  parseZclStatusCode(ctx, x, indent)
}

// ZSE Price Cluster

function parseZseGetCurrentPrice({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 8, x, `${indent}Command Options`)
}

function parseZseGetBillingPeriod({ ctx, x, indent }: ZclParseOptions) {
  parseZclUtcTime(ctx, x, `${indent}Earliest Start Time`)
  parseZclUint(ctx, 32, x, `${indent}Minimum Issuer Event Id`)
  parseZclUint(ctx, 8, x, `${indent}Number of Commands`)
  parseZclBitmap(ctx, 8, x, `${indent}Tariff Type`)
}

function parseZsePublishPrice({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclOctetString(ctx, x, `${indent}Rate Label`)
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUtcTime(ctx, x, `${indent}Current Time`)
  parseZclEnum(ctx, 8, x, `${indent}Unit of Measure`, { 0: 'kWh' })
  parseZclUint(ctx, 16, x, `${indent}Currency`, { 826: 'GBP', 978: 'Euro' })
  parseZclBitmap(ctx, 8, x, `${indent}Price Trailing Digit and Price Tier`)
  parseZclBitmap(ctx, 8, x, `${indent}Number of Price Tiers and Register Tier`)
  parseZclUtcTime(ctx, x, `${indent}Start Time`)
  parseZclUint(ctx, 16, x, `${indent}Duration in Minutes`)
  parseZclUint(ctx, 32, x, `${indent}Price`)
  // NOTE: the Response may contain an additional 19 octets after this
  // parameter. Those 19 octets do not contain meaningful information
  // and so, if present, should be ignored by all parties
  if (x.end - x.index === 19) {
    putBytes(ctx, `${indent}Meaningless Information`, x)
  }
}

function parseZsePublishBlockPeriod({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUtcTime(ctx, x, `${indent}Block Period Start Time`)
  parseZclUint(ctx, 24, x, `${indent}Block Period Duration`)
  parseZclBitmap(ctx, 8, x, `${indent}Block Period Control`)
  parseZclBitmap(ctx, 8, x, `${indent}Block Period Duration Type`)
  parseZclBitmap(ctx, 8, x, `${indent}Tariff Type`)
  parseZclEnum(ctx, 8, x, `${indent}Tariff Resolution Period`)
}

function parseZsePublishConversionFactor({ ctx, x, indent }: ZclParseOptions) {
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUtcTime(ctx, x, `${indent}Start Time`)
  parseZclUint(ctx, 32, x, `${indent}Conversion Factor`)
  parseZclBitmap(ctx, 8, x, `${indent}Conversion Factor Trailing Digit`)
}

function parseZsePublishCalorificValue({ ctx, x, indent }: ZclParseOptions) {
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUtcTime(ctx, x, `${indent}Start Time`)
  parseZclUint(ctx, 32, x, `${indent}Calorific Value`)
  parseZclEnum(ctx, 8, x, `${indent}Calorific Value Unit`)
  parseZclBitmap(ctx, 8, x, `${indent}Calorific Value Trailing Digit`)
}

function parseZsePublishTariffInformation({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUint(ctx, 32, x, `${indent}Issuer Tariff Id`)
  parseZclUtcTime(ctx, x, `${indent}Start Time`)
  parseZclBitmap(ctx, 8, x, `${indent}Tariff Type / Charging Scheme`, {
    0x00: 'TOU Tariff / Delivered Tariff',
    0x10: 'Block Tariff / Delivered Tariff',
  })
  parseZclOctetString(ctx, x, `${indent}Tariff Label`)
  parseZclUint(ctx, 8, x, `${indent}Number of Price Tiers in Use`)
  parseZclUint(ctx, 8, x, `${indent}Number of Block Thresholds in Use`)
  parseZclEnum(ctx, 8, x, `${indent}Unit of Measure`, { 0: 'kWh' })
  parseZclUint(ctx, 16, x, `${indent}Currency`, { 826: 'GBP', 978: 'Euro' })
  parseZclBitmap(ctx, 8, x, `${indent}Price Trailing Digit`)
  parseZclUint(ctx, 32, x, `${indent}Standing Charge`)
  parseZclUint(ctx, 8, x, `${indent}Tier Block Mode`)
  parseZclUint(ctx, 24, x, `${indent}Block Threshold Multiplier`)
  parseZclUint(ctx, 24, x, `${indent}Block Threshold Divisor`)
}

function parseZsePublishPriceMatrix({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUtcTime(ctx, x, `${indent}Start Time`)
  parseZclUint(ctx, 32, x, `${indent}Issuer Tariff Id`)
  parseZclUint(ctx, 8, x, `${indent}Command Index`)
  parseZclUint(ctx, 8, x, `${indent}Number of Commands`)
  parseZclBitmap(ctx, 8, x, `${indent}Sub-payload Control`, {
    0: 'Block or Block/TOU',
    1: 'TOU',
  })
  for (let i = 1; x.index < x.end; i++) {
    parseZclUint(ctx, 8, x, `${indent}Tier / Block Id ` + i)
    parseZclUint(ctx, 32, x, `${indent}Price ` + i)
  }
}

function parseZsePublishBlockThresholds({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUtcTime(ctx, x, `${indent}Start Time`)
  parseZclUint(ctx, 32, x, `${indent}Issuer Tariff Id`)
  parseZclUint(ctx, 8, x, `${indent}Command Index`)
  parseZclUint(ctx, 8, x, `${indent}Number of Commands`)
  parseZclBitmap(ctx, 8, x, `${indent}Sub-payload Control`, {
    1: 'Block thresholds apply to all TOU tiers / block only charging in operation',
  })
  const n = parseZclUint(ctx, 8, x, `${indent}Number of Block Thresholds`)
  for (let i = 1; i <= n; i++) {
    parseZclUint(ctx, 48, x, `${indent}Block Threshold ${i}`)
  }
}

function parseZsePublishBillingPeriod({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUtcTime(ctx, x, `${indent}Billing Period Start Time`)
  parseZclUint(ctx, 24, x, `${indent}Billing Period Duration`)
  parseZclUint(ctx, 8, x, `${indent}Billing Period Duration Type`)
  parseZclUint(ctx, 8, x, `${indent}Tariff Type`)
}

// ZSE Metering Cluster

function parseZseGetSnapshot({ ctx, x, indent }: ZclParseOptions) {
  parseZclUtcTime(ctx, x, `${indent}Earliest Start Time`)
  parseZclUtcTime(ctx, x, `${indent}Latest End Time`)
  parseZclUint(ctx, 8, x, `${indent}Snapshot Offset`)
  parseZclBitmap(ctx, 32, x, `${indent}Snapshot Cause`)
}

function parseZseStartSampling({ ctx, x, indent }: ZclParseOptions) {
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUtcTime(ctx, x, `${indent}Start Sampling Time`)
  parseZclEnum(ctx, 8, x, `${indent}Sample Type`)
  parseZclUint(ctx, 16, x, `${indent}Sample Request Interval`)
  parseZclUint(ctx, 16, x, `${indent}Max Number of Samples`)
}

function parseZseGetSampledData({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 16, x, `${indent}Sample Id`)
  parseZclUtcTime(ctx, x, `${indent}Earliest Sample Time`)
  parseZclEnum(ctx, 8, x, `${indent}Sample Type`)
  parseZclUint(ctx, 16, x, `${indent}Number of Samples`)
}

function parseZseChangeSupply({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUtcTime(ctx, x, `${indent}Request Date Time`)
  parseZclUtcTime(ctx, x, `${indent}Implementation Date Time`)
  parseZclEnum(ctx, 8, x, `${indent}Proposed Supply Status`)
  parseZclBitmap(ctx, 8, x, `${indent}Supply Control Bits`)
}

function parseZseSetSupplyStatus({ ctx, x, indent }: ZclParseOptions) {
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclEnum(ctx, 8, x, `${indent}Supply Tamper State`)
  parseZclEnum(ctx, 8, x, `${indent}Supply Depletion State`)
  parseZclEnum(ctx, 8, x, `${indent}Supply Uncontrolled Flow State`)
  parseZclEnum(ctx, 8, x, `${indent}Low Limit Supply State`)
}

function parseZseSetUncontrolledFlowThreshold({
  ctx,
  x,
  indent,
}: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUint(ctx, 16, x, `${indent}Uncontrolled Flow Threshold`)
  parseZclEnum(ctx, 8, x, `${indent}Unit of Measure`, { 0: 'kWh' })
  parseZclUint(ctx, 16, x, `${indent}Multiplier`)
  parseZclUint(ctx, 16, x, `${indent}Divisor`)
  parseZclUint(ctx, 8, x, `${indent}Stabilisation Period`)
  parseZclUint(ctx, 16, x, `${indent}Measurement Period`)
}

function parseZsePublishPrepaySnapshot({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Snapshot Id`)
  parseZclUtcTime(ctx, x, `${indent}Snapshot Time`)
  parseZclUint(ctx, 8, x, `${indent}Snapshots Found`)
  parseZclUint(ctx, 8, x, `${indent}Command Index`)
  parseZclUint(ctx, 8, x, `${indent}Number of Commands`)
  parseZclBitmap(ctx, 32, x, `${indent}Snapshot Cause`)
  parseZclEnum(ctx, 8, x, `${indent}Snapshot Payload Type`)
  putBytes(ctx, `${indent}Snapshot Sub-payload`, getBytes(x, 0))
  // ZSE Accumulated Debt = SMETS Accumulated Debt Register; ZSE Type 1 Debt Remaining = SMETS Time Debt Registers [1]; ZSE Type 2 Debt Remaining = SMETS Time Debt Registers [2]; ZSE Type 3 Debt Remaining = SMETS Payment Debt Register; ZSE Emergency Credit Remaining = SMETS Emergency Credit Balance; ZSE Credit Remaining = SMETS Meter Balance
  parseZclInt32(ctx, x, `${indent} Accumulated Debt Register`)
  parseZclUint(ctx, 32, x, `${indent} Time Debt Registers [1]`)
  parseZclUint(ctx, 32, x, `${indent} Time Debt Registers [2]`)
  parseZclUint(ctx, 32, x, `${indent} Payment Debt Register`)
  parseZclUint(ctx, 32, x, `${indent} Emergency Credit Balance`)
  parseZclUint(ctx, 32, x, `${indent} Meter Balance`)
}

function parseZsePublishSnapshot({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Snapshot Id`)
  parseZclUtcTime(ctx, x, `${indent}Snapshot Time`)
  parseZclUint(ctx, 8, x, `${indent}Snapshots Found`)
  parseZclUint(ctx, 8, x, `${indent}Command Index`)
  parseZclUint(ctx, 8, x, `${indent}Number of Commands`)
  parseZclBitmap(ctx, 32, x, `${indent}Snapshot Cause`)
  parseZclEnum(ctx, 8, x, `${indent}Snapshot Payload Type`) // 6
  putBytes(ctx, `${indent}Snapshot Sub-payload`, getBytes(x, 0))
  parseZclUint(ctx, 48, x, `${indent} Current Summation Delivered`)
  parseZclUint(ctx, 8, x, `${indent} Number of Tiers in Use`)
  for (let i = 0; i < 4; i++) {
    parseZclUint(ctx, 48, x, `${indent} Tariff TOU Register Matrix [${i + 1}]`)
  }
  parseZclBitmap(
    ctx,
    8,
    x,
    `${indent} Number of Tiers and Block Thresholds in Use`,
  )
  for (let i = 0; i < 4; i++) {
    parseZclUint(
      ctx,
      48,
      x,
      `${indent} Tariff TOU Block Counter Matrix [${i + 1}]`,
    )
  }
}

function parseZseGetSampledDataResponse({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 16, x, `${indent}Sample Id`)
  parseZclUtcTime(ctx, x, `${indent}Sample Start Time`)
  parseZclEnum(ctx, 8, x, `${indent}Sample Type`)
  parseZclUint(ctx, 16, x, `${indent}Sample Request Interval`)
  const n = parseZclUint(ctx, 16, x, `${indent}Number of Samples`)
  for (let i = 1; i <= n; i++) {
    parseZclUint(ctx, 24, x, `${indent}Sample ${i}`)
  }
}

function parseZseSupplyStatusResponse({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUtcTime(ctx, x, `${indent}Implementation Date Time`)
  parseZclEnum(ctx, 8, x, `${indent}Supply Status`)
}

function parseZseStartSamplingResponse({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 16, x, `${indent}Sample Id`)
}

// ZSE Messaging Cluster

function parseZseDisplayMessage({ ctx, x, indent }: ZclParseOptions) {
  parseZclUtcTime(ctx, x, `${indent}Message Id`)
  parseZclBitmap(ctx, 8, x, `${indent}Message Control`)
  parseZclUtcTime(ctx, x, `${indent}Start Time`)
  parseZclUint(ctx, 16, x, `${indent}Duration in Minutes`)
  parseZclOctetString(ctx, x, `${indent}Message`)
  if (x.index < x.end) {
    parseZclBitmap(ctx, 8, x, `${indent}Extended Message Control`)
  }
}

// ZSE Prepayment Cluster

function parseZseSelectAvailableEmergencyCredit({
  ctx,
  x,
  indent,
}: ZclParseOptions) {
  parseZclUtcTime(ctx, x, `${indent}Command Issue Date Time`)
  parseZclEnum(ctx, 8, x, `${indent}Originating Device`, {
    0: 'Energy Service Interface',
  })
}

function parseZseChangeDebt({ ctx, x, indent }: ZclParseOptions) {
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclOctetString(ctx, x, `${indent}Debt Label`)
  parseZclInt32(ctx, x, `${indent}Debt Amount`)
  parseZclUint(ctx, 8, x, `${indent}Debt Recovery Method`, {
    0: 'Time-based debt',
    1: 'Payment-based debt',
  })
  parseZclEnum(ctx, 8, x, `${indent}Debt Amount Type`, {
    1: 'Time-based debt (1) Incremental',
    3: 'Time-based debt (2) Incremental',
    5: 'Payment-based debt Incremental',
  })
  parseZclUint(ctx, 32, x, `${indent}Debt Recovery Start Time`)
  parseZclUint(ctx, 16, x, `${indent}Debt Recovery Collection Time`)
  parseZclEnum(ctx, 8, x, `${indent}Debt Recovery Frequency`, {
    0: 'Hourly',
    1: 'Daily',
  })
  parseZclInt32(ctx, x, `${indent}Debt Recovery Amount`)
  parseZclEnum(ctx, 16, x, `${indent}Debt Recovery Balance Percentage`)
}

function parseZseEmergencyCreditSetup({ ctx, x, indent }: ZclParseOptions) {
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUtcTime(ctx, x, `${indent}Start Time`)
  parseZclUint(ctx, 32, x, `${indent}Emergency Credit Limit`)
  parseZclUint(ctx, 32, x, `${indent}Emergency Credit Threshold`)
}

function parseZseConsumerTopUp({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 8, x, `${indent}Originating Device`)
  parseZclUtrn(ctx, x, `${indent}Top Up Code`)
}

function parseZseCreditAdjustment({ ctx, x, indent }: ZclParseOptions) {
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUtcTime(ctx, x, `${indent}Start Time`)
  parseZclUint(ctx, 8, x, `${indent}Credit Adjustment Type`)
  parseZclInt32(ctx, x, `${indent}Credit Adjustment Value`)
}

function parseZseChangePaymentMode({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUtcTime(ctx, x, `${indent}Implementation Date Time`)
  parseZclUint(ctx, 16, x, `${indent}Proposed Payment Control Configuration`, {
    0x0497:
      'Prepayment mode<br>Suspend Debt Emergency = True<br>Suspend Debt Disabled = True',
    0x0097:
      'Prepayment mode<br>Suspend Debt Emergency = True<br>Suspend Debt Disabled = False',
    0x0c97:
      'Prepayment mode<br>Suspend Debt Emergency = False<br>Suspend Debt Disabled = True',
    0x0897:
      'Prepayment mode<br>Suspend Debt Emergency = False<br>Suspend Debt Disabled = False',
    0x0c94: 'Credit mode',
  })
  parseZclInt32(ctx, x, `${indent}Cut Off Value`)
}

function parseZseGetPrepaySnapshot({ ctx, x, indent }: ZclParseOptions) {
  parseZclUtcTime(ctx, x, `${indent}Earliest Start Time`)
  parseZclUtcTime(ctx, x, `${indent}Latest End Time`)
  parseZclUint(ctx, 8, x, `${indent}Snapshot Offset`)
  parseZclBitmap(ctx, 32, x, `${indent}Snapshot Cause`, { 1: 'General' })
}

function parseZseGetTopUpLog({ ctx, x, indent }: ZclParseOptions) {
  parseZclUtcTime(ctx, x, `${indent}Latest End Time`)
  parseZclUint(ctx, 8, x, `${indent}Number of Records`)
}

function parseZseSetLowCreditWarningLevel({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Low Credit Warning Level`)
}

function parseZseGetDebtRepaymentLog({ ctx, x, indent }: ZclParseOptions) {
  parseZclUtcTime(ctx, x, `${indent}Latest End Time`)
  parseZclUint(ctx, 8, x, `${indent}Number of Debts`)
  parseZclEnum(ctx, 8, x, `${indent}Debt Type`)
}

function parseZseSetMaximumCreditLimit({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUtcTime(ctx, x, `${indent}Implementation Date Time`)
  parseZclUint(ctx, 32, x, `${indent}Maximum Credit Level`)
  parseZclUint(ctx, 32, x, `${indent}Maximum Credit Per Top Up`)
}

function parseZseSetOverallDebtCap({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUtcTime(ctx, x, `${indent}Implementation Date Time`)
  parseZclInt32(ctx, x, `${indent}Overall Debt Cap`)
}

function parseZseChangePaymentModeResponse({
  ctx,
  x,
  indent,
}: ZclParseOptions) {
  parseZclUint(ctx, 8, x, `${indent}Friendly Credit`)
  parseZclUint(ctx, 32, x, `${indent}Friendly Credit Calendar ID`)
  parseZclUint(ctx, 32, x, `${indent}Emergency Credit Limit`)
  parseZclUint(ctx, 32, x, `${indent}Emergency Credit Threshold`)
}

function parseZseConsumerTopUpResponse({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 8, x, `${indent}Result Type`)
  parseZclInt32(ctx, x, `${indent}Top Up Value`)
  parseZclUint(ctx, 8, x, `${indent}Source of Top Up`)
  parseZclInt32(ctx, x, `${indent}Credit Remaining`)
}

function parseZsePublishTopUpLog({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 8, x, `${indent}Command Index`)
  parseZclUint(ctx, 8, x, `${indent}Number of Commands`)
  for (let i = 1; x.index < x.end; i++) {
    parseZclUtrn(ctx, x, `${indent}Top Up Code ${i}`)
    parseZclInt32(ctx, x, `${indent}Top Up Amount ${i}`)
    parseZclUtcTime(ctx, x, `${indent}Top Up Time ${i}`)
  }
}

function parseZsePublishDebtLog({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 8, x, `${indent}Command Index`)
  parseZclUint(ctx, 8, x, `${indent}Number of Commands`)
  for (let i = 1; x.index < x.end; i++) {
    parseZclUtcTime(ctx, x, `${indent}Collection Time ${i}`)
    parseZclUint(ctx, 32, x, `${indent}Amount Collected ${i}`)
    parseZclEnum(ctx, 8, x, `${indent}Debt Type ${i}`)
    parseZclUint(ctx, 32, x, `${indent}Outstanding Debt ${i}`)
  }
}

// ZSE Calendar Cluster

function parseZseGetDayProfiles({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclUint(ctx, 32, x, `${indent}Issuer Calendar Id`)
  parseZclUint(ctx, 8, x, `${indent}Start Day Id`)
  parseZclUint(ctx, 8, x, `${indent}Number of Days`)
}

function parseZseGetWeekProfiles({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclUint(ctx, 32, x, `${indent}Issuer Calendar Id`)
  parseZclUint(ctx, 8, x, `${indent}Start Week Id`)
  parseZclUint(ctx, 8, x, `${indent}Number of Weeks`)
}

function parseZseGetSeasons({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclUint(ctx, 32, x, `${indent}Issuer Calendar Id`)
}

function parseZseGetSpecialDays({ ctx, x, indent }: ZclParseOptions) {
  parseZclUtcTime(ctx, x, `${indent}Start Time`)
  parseZclUint(ctx, 8, x, `${indent}Number of Events`)
  parseZclCalendarUint(ctx, 8, x, `${indent}Calendar Type`)
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclUint(ctx, 32, x, `${indent}Issuer Calendar Id`)
}

function parseZsePublishCalendar({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUint(ctx, 32, x, `${indent}Issuer Calendar Id`)
  parseZclUtcTime(ctx, x, `${indent}Start Time`)
  parseZclCalendarUint(ctx, 8, x, `${indent}Calendar Type`)
  parseZclUint(ctx, 8, x, `${indent}Calendar Time Reference`)
  parseZclOctetString(ctx, x, `${indent}Calendar Name`)
  parseZclUint(ctx, 8, x, `${indent}Number of Seasons`)
  parseZclUint(ctx, 8, x, `${indent}Number of Week Profiles`)
  parseZclUint(ctx, 8, x, `${indent}Number of Day Profiles`)
}

function parseZsePublishDayProfile({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUint(ctx, 32, x, `${indent}Issuer Calendar Id`)
  parseZclUint(ctx, 8, x, `${indent}Day Id`)
  const entries = parseZclUint(ctx, 8, x, `${indent}Number of Schedule Entries`)
  parseZclUint(ctx, 8, x, `${indent}Command Index`)
  parseZclUint(ctx, 8, x, `${indent}Number of Commands`)
  const calendarType = parseZclCalendarUint(ctx, 8, x, `${indent}Calendar Type`)
  for (let i = 1; i <= entries; i++) {
    const dec = parseNumberLE(x, 2)
    let hour: string | number = Math.floor(dec / 60)
    if (hour < 10) hour = '0' + hour
    let minute: string | number = Math.floor(dec % 60)
    if (minute < 10) minute = '0' + minute
    const time = '' + hour + ':' + minute
    putBytes(
      ctx,
      `${indent}Schedule Entry ${i} Start Time`,
      getBytes(x, 2),
      time,
    )
    if (calendarType === 0x00)
      parseZclUint(ctx, 8, x, `${indent}Price Tier ${i}`)
    else parseZclUint(ctx, 8, x, `${indent}Friendly Credit Enable ${i}`)
  }
}

function parseZsePublishWeekProfile({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUint(ctx, 32, x, `${indent}Issuer Calendar Id`)
  parseZclUint(ctx, 8, x, `${indent}Week Id`)
  putBytes(ctx, `${indent}Day Id Refs (Monday to Sunday)`, getBytes(x, 7))
}

function parseZsePublishSeasons({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUint(ctx, 32, x, `${indent}Issuer Calendar Id`)
  parseZclUint(ctx, 8, x, `${indent}Command Index`)
  parseZclUint(ctx, 8, x, `${indent}Number of Commands`)
  for (let i = 1; x.index < x.end; i++) {
    parseZclDate(ctx, x, `${indent}Season ${i} Start Date`)
    parseZclUint(ctx, 8, x, `${indent}Season ${i} Week Id Ref`)
  }
}

function parseZsePublishSpecialDays({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUint(ctx, 32, x, `${indent}Issuer Calendar Id`)
  parseZclUtcTime(ctx, x, `${indent}Start Time`)
  parseZclCalendarUint(ctx, 8, x, `${indent}Calendar Type`)
  const numberOfSpecialDays = parseZclUint(
    ctx,
    8,
    x,
    `${indent}Number of Special Days`,
  )
  parseZclUint(ctx, 8, x, `${indent}Command Index`)
  parseZclUint(ctx, 8, x, `${indent}Number of Commands`)
  for (let i = 1; i <= numberOfSpecialDays; i++) {
    parseZclDate(ctx, x, `${indent}Special Day ${i} Date`)
    parseZclUint(ctx, 8, x, `${indent}Special Day ${i} Day Id Ref`)
  }
}

// ZSE Device Management Cluster

function parseZseReportEventConfiguration({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 8, x, `${indent}Command Index`)
  parseZclUint(ctx, 8, x, `${indent}Total Commands`)
  for (let i = 1; x.index < x.end; i++) {
    parseZclUint(ctx, 16, x, `${indent}Event Id ${i}`)
    parseZclBitmap(ctx, 8, x, `${indent}Event Configuration ${i}`)
  }
}

function parseZsePublishChangeOfTenancy({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclBitmap(ctx, 8, x, `${indent}Tariff Type`)
  parseZclUtcTime(ctx, x, `${indent}Implementation Date Time`)
  parseZclBitmap(ctx, 32, x, `${indent}Proposed Tenancy Change Control`)
}

function parseZsePublishChangeOfSupplier({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 32, x, `${indent}Current Provider Id`)
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclBitmap(ctx, 8, x, `${indent}Tariff Type`)
  parseZclUint(ctx, 32, x, `${indent}Proposed Provider Id`)
  parseZclUtcTime(ctx, x, `${indent}Provider Change Implementation Time`)
  parseZclBitmap(ctx, 32, x, `${indent}Provider Change Control`)
  parseZclOctetString(ctx, x, `${indent}Proposed Provider Name`)
  parseZclOctetString(ctx, x, `${indent}Proposed Provider Contact Details`)
}

function parseZseRequestNewPasswordResponse({
  ctx,
  x,
  indent,
}: ZclParseOptions) {
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUtcTime(ctx, x, `${indent}Implementation Date Time`)
  parseZclUint(ctx, 16, x, `${indent}Duration in Minutes`)
  parseZclEnum(ctx, 8, x, `${indent}Password Type`)
  parseZclOctetString(ctx, x, `${indent}Password`)
}

function parseZseUpdateSiteId({ ctx, x, indent }: ZclParseOptions) {
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUtcTime(ctx, x, `${indent}Site Id Time`)
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclOctetString(ctx, x, `${indent}Site Id`)
}

function parseZseSetEventConfiguration({ ctx, x, indent }: ZclParseOptions) {
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUtcTime(ctx, x, `${indent}Start Date Time`)
  parseZclBitmap(ctx, 8, x, `${indent}Event Configuration`)
  parseZclEnum(ctx, 8, x, `${indent}Configuration Control`)
  // Event Configuration Payload (Apply by List)
  const n = parseZclUint(ctx, 8, x, `${indent}Number of Events`)
  for (let i = 1; i <= n; i++) {
    parseZclUint(ctx, 16, x, `${indent}Event Id ${i}`)
  }
}

function parseZseGetEventConfiguration({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 16, x, `${indent}Event Id`)
}

function parseZseUpdateCin({ ctx, x, indent }: ZclParseOptions) {
  parseZclUtcTime(ctx, x, `${indent}Issuer Event Id`)
  parseZclUtcTime(ctx, x, `${indent}CIN Implementation Time`)
  parseZclUint(ctx, 32, x, `${indent}Provider Id`)
  parseZclOctetString(ctx, x, `${indent}Customer Id Number`)
}

// ZSE Event Cluster

function parseZseGetEventLog({ ctx, x, indent }: ZclParseOptions) {
  parseZclBitmap(ctx, 8, x, `${indent}Event Control / Log Id`)
  parseZclUint(ctx, 16, x, `${indent}Event Id`)
  parseZclUtcTime(ctx, x, `${indent}Start Time`)
  parseZclUtcTime(ctx, x, `${indent}End Time`)
  parseZclUint(ctx, 8, x, `${indent}Number of Events`)
  parseZclUint(ctx, 16, x, `${indent}Event Offset`)
}

function parseZseClearEventLogRequest({ ctx, x, indent }: ZclParseOptions) {
  parseZclBitmap(ctx, 8, x, `${indent}Log Id`)
}

function parseZsePublishEventLog({ ctx, x, indent }: ZclParseOptions) {
  parseZclUint(ctx, 16, x, `${indent}Number of Events`)
  parseZclUint(ctx, 8, x, `${indent}Command Index`)
  parseZclUint(ctx, 8, x, `${indent}Total Commands`)
  parseZclBitmap(ctx, 8, x, `${indent}Log Payload Control`)
  for (let i = 1; x.index < x.end; i++) {
    parseLogIdBitmap(ctx, 8, x, `${indent}Log Id ${i}`)
    parseZclUintHex(ctx, 16, x, `${indent}Event Id ${i}`)
    parseZclUtcTime(ctx, x, `${indent}Event Time ${i}`)
    parseZclOctetString(ctx, x, `${indent}Event Data ${i}`)
  }
}

function parseZseClearEventLogResponse({ ctx, x, indent }: ZclParseOptions) {
  parseZclBitmap(ctx, 8, x, `${indent}Cleared Event Logs`)
}

// ZCL Types

function parseZclUint(
  ctx: Context,
  bits: number,
  x: Slice,
  name: string,
  values?: Record<number, string>,
) {
  let value = 0
  const bytes = bits / 8
  value = parseNumberLE(x, bytes)
  putBytes(
    ctx,
    name,
    getBytes(x, bytes),
    values?.[value] ?? String(value),
    /*tooltip(
        (values && (values[value] || 'Unknown')) || value,
        toHex(value, bits)
      )*/
  )
  return value
}

function parseZclUintHex(ctx: Context, bits: number, x: Slice, name: string) {
  let value = 0
  const bytes = bits / 8
  value = parseNumberLE(x, bytes)
  putBytes(ctx, name, getBytes(x, bytes), '0x' + value.toString(16))
  return value
}

function getCalendarTypeName(/*int*/ calendarType: number) {
  const names: Record<number, string> = {
    0x00: 'Delivered Calendar',
    0x01: 'Received Calendar',
    0x02: 'Delivered and Received Calendar',
    0x03: 'Friendly Credit Calendar',
    0x04: 'Auxiliary Load Switch Calendar',
  }
  if (calendarType <= 0x04) return names[calendarType]
  else return 'Reserved'
}

function parseZclCalendarUint(
  ctx: Context,
  bits: number,
  x: Slice,
  name: string,
) {
  const bytes = bits / 8 //useless
  const calendarType = x.input.byte(x.index)
  putBytes(ctx, name, getBytes(x, bytes), getCalendarTypeName(calendarType))
  return calendarType
}

function parseZclInt32(ctx: Context, x: Slice, name: string) {
  let value = parseNumberLE(x, 4)
  if (value > 0x7fffffff) value -= 0x100000000
  putBytes(ctx, name, getBytes(x, 4), String(value))
  return value
}

function parseZclOctetString(ctx: Context, x: Slice, name: string) {
  const length = x.input.byte(x.index)
  let value = ''
  for (let i = 0; i < length; i++) {
    value += String.fromCharCode(x.input.byte(x.index + 1 + i))
  }
  const printableValue = value.replace(/[^\x20-\x7E]/g, ' ')
  putBytes(ctx, name, getBytes(x, 1 + length), printableValue)
}

function parseZclBitmap(
  ctx: Context,
  bits: number,
  x: Slice,
  name: string,
  values?: Record<number, string>,
) {
  const number = parseNumberLE(x, bits / 8)
  const value = toHex(number, bits)
  putBytes(ctx, name, getBytes(x, bits / 8), values?.[number] ?? value)
}

function getLogIdType(/*int*/ logIdType: number) {
  const names: Record<number, string> = {
    0x00: 'All logs',
    0x01: 'Tamper Log',
    0x02: 'Fault Log',
    0x03: 'General Event Log',
    0x04: 'Security Event Log',
    0x05: 'Network Event Log',
  }
  if (logIdType <= 0x05) return names[logIdType]
  else return 'Reserved'
}

function parseLogIdBitmap(ctx: Context, bits: number, x: Slice, name: string) {
  const logIdType = x.input.byte(x.index)
  putBytes(ctx, name, getBytes(x, bits / 8), getLogIdType(logIdType))
}

function parseZclEnum(
  ctx: Context,
  bits: number,
  x: Slice,
  name: string,
  values?: Record<number, string>,
) {
  parseZclUint(ctx, bits, x, name, values)
}

function parseZclDate(ctx: Context, x: Slice, name: string) {
  const year = x.input.byte(x.index)
  const month = x.input.byte(x.index + 1)
  const dayOfMonth = x.input.byte(x.index + 2)
  const dayOfWeek = x.input.byte(x.index + 3)

  //Day
  let hday: string
  if (dayOfMonth === 255) hday = 'every day'
  else if (dayOfMonth === 0xfd)
    hday = '2nd last ' + daysInWeek[dayOfWeek] + ' of'
  else if (dayOfMonth === 0xfe) hday = 'last ' + daysInWeek[dayOfWeek] + ' of'
  else if (dayOfMonth < 10) hday = '0' + dayOfMonth
  else hday = String(dayOfMonth)

  //Month
  let hmon: string
  if (month === 255) hmon = 'every month of'
  else if (month === 0xfd) hmon = 'DST-end month of'
  else if (month === 0xfe) hmon = 'DST-begin month of'
  else hmon = monthsInYear[month]

  //Year
  let hyear: string
  if (year === 255) hyear = 'every year'
  else hyear = String(1900 + year)

  const date = `${hday} ${hmon} ${hyear}`
  putBytes(ctx, name, getBytes(x, 4), date)
}

function parseGbzTime(ctx: Context, x: Slice, name: string) {
  const value = parseNumber(x, 4)
  putBytes(ctx, name, getBytes(x, 4), toUtcTimeString(value))
}

function parseZclUtcTime(ctx: Context, x: Slice, name: string) {
  const value = parseNumberLE(x, 4)
  putBytes(ctx, name, getBytes(x, 4), toUtcTimeString(value))
}

function toUtcTimeString(value: number) {
  let text = ''
  if (value !== 0 && value !== 0xffffffff) {
    const secondsSince2000 = value
    const secondsSince1970 = secondsSince2000 + 946684800
    const millisecondsSince1970 = secondsSince1970 * 1000
    const d = new Date(millisecondsSince1970)
    text = d.getUTCFullYear() + '-'
    const month = d.getUTCMonth() + 1
    if (month < 10) text += '0'
    text += month + '-'
    const day = d.getUTCDate()
    if (day < 10) text += '0'
    text += day + ' '
    const hour = d.getUTCHours()
    if (hour < 10) text += '0'
    text += hour + ':'
    const minute = d.getUTCMinutes()
    if (minute < 10) text += '0'
    text += minute + ':'
    const second = d.getUTCSeconds()
    if (second < 10) text += '0'
    text += second
  }
  return text
}

function parseZclUtrn(ctx: Context, x: Slice, name: string) {
  let utrn = ''
  for (let i = 0; i < 20; i++)
    utrn += String.fromCharCode(x.input.byte(x.index + 1 + i))
  const pptd = [
    0, 0,
  ] /* two 32-bit numbers [ least significat, most significant ] */
  for (let i = 0; i < 19; i++) {
    const digit = utrn.charCodeAt(i) - 0x30
    const pptd0 = pptd[0] * 10 + digit
    pptd[0] = Math.floor(pptd0 % 0x100000000)
    const carry = Math.floor(pptd0 / 0x100000000)
    pptd[1] = pptd[1] * 10 + carry /* 304E2FF674C64 */
  }
  const pptdSubtrahend = [
    0x714a0000, 0x669d529b,
  ] /* 7,394,156,990,786,306,048 */
  const ptut = []
  if (pptd[0] > pptdSubtrahend[0]) {
    ptut[0] = pptd[0] - pptdSubtrahend[0]
    ptut[1] = pptd[1] - pptdSubtrahend[1]
  } else {
    ptut[0] = pptd[0] - pptdSubtrahend[0] + 0x100000000
    ptut[1] = pptd[1] - pptdSubtrahend[1] - 1
  }
  const ptutValue = ptut[1] & 0x1fff
  const ptutValueClass = (ptut[1] >> 13) & 3
  putBytes(
    ctx,
    name,
    getBytes(x, 21),
    'UTRN: ' +
      utrn +
      ', PTUT Value Class: ' +
      ptutValueClass +
      ', PTUT Value: ' +
      ptutValue,
  )
}

function parseZclStatusCode(ctx: Context, x: Slice, indent: string) {
  const names: Record<number, string> = {
    0x00: 'Success',
    0x01: 'Failure',
    0x7e: 'Not Authorized',
    0x7f: 'Reserved Field Not Zero',
    0x80: 'Malformed Command',
    0x81: 'Unsup Cluster Command',
    0x82: 'Unsup General Command',
    0x83: 'Unsup Manuf Cluster Command',
    0x84: 'Unsup Manuf General Command',
    0x85: 'Invalid Field',
    0x86: 'Unsupported Attribute',
    0x87: 'Invalid Value',
    0x88: 'Read Only',
    0x89: 'Insufficient Space',
    0x8a: 'Duplicate Exists',
    0x8b: 'Not Found',
    0x8c: 'Unreportable Attribute',
    0x8d: 'Invalid Data Type',
    0x8e: 'Invalid Selector',
    0x8f: 'Write Only',
    0x90: 'Inconsistent Startup State',
    0x91: 'Defined Out Of Band',
    0x92: 'Inconsistent',
    0x93: 'Action Denied',
    0x94: 'Timeout',
    0x95: 'Abort',
    0x96: 'Invalid Image',
    0x97: 'Wait For Data',
    0x98: 'No Image Available',
    0x99: 'Require More Image',
    0xc0: 'Hardware Failure',
    0xc1: 'Software Failure',
    0xc2: 'Calibration Error',
  }
  const value = x.input.byte(x.index)
  const name = names[value] || ''
  putBytes(ctx, `${indent}Status Code`, getBytes(x, 1), name)
  return value
}
