/*
 * Created on Mon Jul 31 2023
 *
 * Copyright (c) 2023 Smart DCC Limited
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

import type {
  DayProfileName,
  DayProfiles,
  NumberRange,
  ProfileSchedule,
  Season,
  Seasons,
  Tariff,
  WeekProfile,
  WeekProfiles,
  SpecialDay,
  SpecialDays,
  BlockAction,
  Blocks,
  TOUs,
} from '@smartdcc/duis-templates'
import { MinimizedParsedMessage } from './context'
import { inspect } from 'node:util'

export interface DLMSDateTime {
  year?: number
  month?: number
  dayOfMonth?: number
  dayOfWeek?: number
}

export function decodeDLMSDateTime(
  b: Buffer,
  logger?: (msg: string) => void,
): DLMSDateTime | null {
  if (b.length !== 12 && b.length !== 5) {
    logger?.('buffer should be 12 (date time) or 5 (date) bytes')
    return null
  }

  const ret: DLMSDateTime = {}

  const year = (b[0] << 8) | b[1]
  if (year !== 0xffff) {
    ret.year = year
  }

  const month = b[2]
  if (month === 0xfd || month === 0xfe) {
    logger?.(
      `month specified as ${month.toString(
        16,
      )} but daylight_savings_end and daylight_savings_begin are not supported`,
    )
    return null
  }
  if (month !== 0xff) {
    ret.month = month
  }

  const dayOfMonth = b[3]
  if (dayOfMonth !== 0xff) {
    ret.dayOfMonth = dayOfMonth
  }

  const dayOfWeek = b[4]
  if (dayOfWeek !== 0xff) {
    ret.dayOfWeek = dayOfWeek
  }

  if (b.length === 12) {
    const time = b.subarray(5, 9)
    if (time.some((x) => x !== 0)) {
      logger?.(`time should be 00:00:00 but found ${time.toString('hex')}`)
      return null
    }

    const deviation = (b[9] << 8) | b[10]
    if (deviation !== 0x8000 && deviation !== 0) {
      logger?.(
        `deviation should be in UTC but ${deviation.toString(16)} specified`,
      )
      return null
    }

    if (b[11] !== 0xff) {
      logger?.('expected clock status to not be specified')
      return null
    }
  }

  return ret
}

export function minifyList(l: number[]): number[] {
  while (l[l.length - 1] === 0) {
    l = l.slice(0, l.length - 1)
  }
  return l
}

export function decodeECS24(
  message: MinimizedParsedMessage,
  logger?: (msg: string) => void,
): Tariff | null {
  if (
    message['Grouping Header']?.['Other Information Length'].children?.[
      'Message Code'
    ].notes !== 'ECS24 Read ESME Tariff Data'
  ) {
    logger?.('wrong message code')
    return null
  }
  if (message['Grouping Header']?.['CRA Flag']?.notes !== 'Response') {
    logger?.('not a response')
    return null
  }

  const ListofAccessResponseSpecification =
    message.Payload?.['DLMS Access Response'].children?.[
      'List of Access Response Specification'
    ].children ?? {}

  if (
    Object.keys(ListofAccessResponseSpecification).filter((key) => {
      const result =
        ListofAccessResponseSpecification[key].children?.['Data Access Result']
          ?.notes
      if (result !== 'Success') {
        logger?.(`${key} data access result was not "Success": ${result}`)
        return false
      }
      return true
    }).length !== 17
  ) {
    logger?.('ECS24 payload was not successful, unable to decode')
    return null
  }

  const ListofAccessResponseData =
    message.Payload?.['DLMS Access Response'].children?.[
      'List of Access Response Data'
    ].children ?? {}

  /*
    As the above checks have passed, it is assumed that the payload is of the correct format
    correct format. So error cases are not tested for.
  */

  /* 0 (Primary)ActiveTariffPrice.value */
  /* n/a */

  /* 1 (Primary)ActiveTariffPrice.scale */
  /* n/a */

  /* 2 TariffSwitchingTable.currentSeasons */
  const currentSeasonsDLMS =
    ListofAccessResponseData['[2] Array'].children ?? {}
  const currentSeasonsDLMS_len = Number(
    ListofAccessResponseData['[2] Array']?.notes?.split(' ')[0],
  )
  const seasons = Array.from(Array(currentSeasonsDLMS_len).keys()).map(
    (i): Season | null => {
      const s = currentSeasonsDLMS[`[${i}] Structure`]?.children ?? {}
      logger?.(
        `parsing season ${i}: ${inspect(s, {
          breakLength: Infinity,
          compact: true,
        })}`,
      )
      const date = decodeDLMSDateTime(
        Buffer.from(
          s['[1] Octet String']?.hex.replace(/ /g, ''),
          'hex',
        ).subarray(2),
        logger,
      ) as DLMSDateTime
      return {
        name: `${s['[0] Octet String']?.notes}`.slice(1, -1),
        weekProfile: Number(s['[2] Octet String'].hex.split(' ').slice(-1)[0]),
        ...date,
      }
    },
  ) as Seasons

  /* 3 TariffSwitchingTable.currentWeeks */
  const currentWeeksDLMS = ListofAccessResponseData['[3] Array'].children ?? {}
  const currentWeeksDLMS_len = Number(
    ListofAccessResponseData['[3] Array']?.notes?.split(' ')[0],
  )
  const weekProfiles = Array.from(Array(currentWeeksDLMS_len).keys())
    .map((i): { id: number; weekProfile: WeekProfile } => {
      const wp = currentWeeksDLMS[`[${i}] Structure`]?.children ?? {}
      return {
        id: Number(wp['[0] Octet String'].hex.split(' ').slice(-1)[0]),
        weekProfile: [
          Number(wp['[1] Unsigned']?.notes) as DayProfileName,
          Number(wp['[2] Unsigned']?.notes) as DayProfileName,
          Number(wp['[3] Unsigned']?.notes) as DayProfileName,
          Number(wp['[4] Unsigned']?.notes) as DayProfileName,
          Number(wp['[5] Unsigned']?.notes) as DayProfileName,
          Number(wp['[6] Unsigned']?.notes) as DayProfileName,
          Number(wp['[7] Unsigned']?.notes) as DayProfileName,
        ],
      }
    })
    .sort((a, b) => a.id - b.id)
    .map(({ weekProfile }) => weekProfile) as WeekProfiles

  /* 4 TariffSwitchingTable.currentDayIdentifiers */
  const currentDayIdentifiersDLMS =
    ListofAccessResponseData['[4] Array'].children ?? {}
  const currentDayIdentifiersDLMS_len = Number(
    ListofAccessResponseData['[4] Array']?.notes?.split(' ')[0],
  )
  const dayProfiles = Array.from(Array(currentDayIdentifiersDLMS_len).keys())
    .map((i): { id: number; dayProfile: ProfileSchedule[] } => {
      const dp = currentDayIdentifiersDLMS[`[${i}] Structure`]?.children ?? {}
      const pss = dp['[1] Array']?.children ?? {}
      const pss_len = Number(dp['[1] Array']?.notes?.split(' ')[0])

      return {
        id: Number(dp['[0] Unsigned']?.notes),
        dayProfile: Array.from(Array(pss_len).keys()).map(
          (i): ProfileSchedule => {
            const ps = pss[`[${i}] Structure`]?.children ?? {}
            const startTimeBinary = Buffer.from(
              ps['[0] Octet String']?.hex.replace(/ /g, ''),
              'hex',
            )
            const startTime =
              startTimeBinary[2] * 60 * 60 +
              startTimeBinary[3] * 60 +
              startTimeBinary[4]
            const action = Number(ps['[2] Long Unsigned']?.notes)
            if (action >= 1 && action <= 48) {
              return {
                startTime,
                action: action as NumberRange<48>,
                mode: 'tou',
              }
            }
            if (action >= 101 && action <= 108) {
              return {
                startTime,
                action: (action - 100) as NumberRange<8>,
                mode: 'block',
              }
            }
            /* action 201 ... 204 is secondary element tou */
            logger?.(
              `failed to interpret action ${action}, setting default of 1`,
            )
            return {
              startTime,
              action: 1,
              mode: 'tou',
            }
          },
        ),
      }
    })
    .sort((a, b) => a.id - b.id)
    .map(({ dayProfile }) => dayProfile) as DayProfiles

  /* 5 TariffSwitchingTable.specialDays */
  const specialDaysDLMS = ListofAccessResponseData['[5] Array'].children ?? {}
  const specialDaysDLMS_len = Number(
    ListofAccessResponseData['[5] Array']?.notes?.split(' ')[0],
  )
  const specialDays = Array.from(Array(specialDaysDLMS_len).keys())
    .map((i): { id: number; specialDay: SpecialDay } => {
      const sd = specialDaysDLMS[`[${i}] Structure`]?.children ?? {}
      const date = decodeDLMSDateTime(
        Buffer.from(
          sd['[1] Octet String']?.hex.replace(/ /g, ''),
          'hex',
        ).subarray(2),
        logger,
      ) as DLMSDateTime
      return {
        id: Number(sd['[0] Long Unsigned']?.notes),
        specialDay: {
          ...date,
          dayProfile: Number(sd['[2] Unsigned'].notes),
        },
      }
    })
    .sort((a, b) => a.id - b.id)
    .map(({ specialDay }) => specialDay) as SpecialDays

  /* 6-13 TariffThresholdMatrixBlock.thresholdCurrent */
  const thresholds: { thresholds: number[] }[] = []
  for (let z = 6; z < 14; z++) {
    const thresholdCurrentDLMS =
      ListofAccessResponseData[`[${z}] Array`].children ?? {}
    const thresholdCurrentDLMS_len = Number(
      ListofAccessResponseData[`[${z}] Array`]?.notes?.split(' ')[0],
    )
    const thresholdCurrent = Array.from(
      Array(thresholdCurrentDLMS_len).keys(),
    ).map((i): number => {
      return Number(thresholdCurrentDLMS[`[${i}] Double Long Unsigned`].notes)
    })

    thresholds.push({
      thresholds: thresholdCurrent,
    })
  }

  /* 14 CurrencyUnit.valueCurrent */

  /* 15 StandingCharge */
  const standingChargeDLMS =
    ListofAccessResponseData['[15] Structure'].children ?? {}
  const standingChargeScale = Number(
    standingChargeDLMS['[0] Structure']?.children?.['[1] Integer']?.notes,
  )
  const standingCharge = Number(
    standingChargeDLMS['[2] Array']?.children?.['[0] Structure']?.children?.[
      '[1] Long'
    ]?.notes,
  )

  /* 16 Charge */
  const chargeDLMS = ListofAccessResponseData['[16] Structure'].children ?? {}
  const priceScale = Number(
    chargeDLMS['[0] Structure']?.children?.['[1] Integer']?.notes,
  )
  /* list of 80 charges initialised to 0, 48 for tou and 32 for block */
  const charges = Array<number>(80).fill(0)
  const chargesDLMS = chargeDLMS['[2] Array']?.children ?? {}
  const chargesDLMS_len = Number(chargeDLMS['[2] Array']?.notes?.split(' ')[0])
  for (let i = 0; i < chargesDLMS_len; i++) {
    // todo: keep eye on whether some meters return out of order results
    /*
    const id = parseInt(
      chargesDLMS[`[${i}] Structure`].children?.['[0] Octet String']?.hex
        .split(' ')
        .slice(-1)[0] as string,
      16,
    )
    */

    const c = Number(
      chargesDLMS[`[${i}] Structure`].children?.['[1] Long']?.notes,
    )

    charges[i] = c
  }

  /* assemble the block actions */
  const blocks = thresholds.map((t, i): BlockAction => {
    const b = 48 + i
    const prices = [
      charges[b],
      charges[b + 8],
      charges[b + 8 * 2],
      charges[b + 8 * 3],
    ]
    return {
      ...t,
      prices: prices.slice(0, t.thresholds.length + 1),
    } as BlockAction
  }) as Blocks

  return {
    seasons,
    weekProfiles,
    dayProfiles,
    specialDays,
    tous: minifyList(charges.slice(0, 48)) as TOUs,
    blocks,
    pricing: {
      priceScale,
      standingCharge,
      standingChargeScale,
    },
  }
}
