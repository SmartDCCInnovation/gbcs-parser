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

export class Uint8ArrayWrapper {
  constructor(readonly buffer: Uint8Array) {}

  byte(i: number): number {
    if (i >= 0 && i < this.buffer.length) {
      return this.buffer[i]
    }
    throw new Error('out of bounds')
  }

  get length() {
    return this.buffer.length
  }

  toString(): string {
    return this.buffer.toString()
  }
}

export interface Slice {
  input: Uint8ArrayWrapper
  index: number
  end: number
}

export const monthsInYear: Record<number, string> = {
  1: 'January',
  2: 'February',
  3: 'March',
  4: 'April',
  5: 'May',
  6: 'June',
  7: 'July',
  8: 'August',
  9: 'September',
  10: 'October',
  11: 'November',
  12: 'December',
}

export const daysInWeek: Record<number, string> = {
  1: 'Monday',
  2: 'Tuesday',
  3: 'Wednesday',
  4: 'Thursday',
  5: 'Friday',
  6: 'Saturday',
  7: 'Sunday',
  0xff: 'day',
}

export const messageCodes: Record<number, string> = {
  0x0001: 'CCS01 Add Device to CHF device log',
  0x0002: 'CCS02 Remove device from CHF device log',
  0x0003: 'CCS03 Restore CHF Device Log',
  0x0007: 'CS01a Apply Prepayment Top Up to an ESME',
  0x0008: 'CS02a Provide Security Credentials Details',
  0x000a: 'CS02c Issue Security Credentials',
  0x000b: 'CS02d Update Device Certificates on Device',
  0x000c: 'CS02e Provide Device Certificates from Device',
  0x000d: 'CS03A1 Method A Join (Meter)',
  0x000e: 'CS03B Method B Join',
  0x000f: 'CS04AC Method A or C Unjoin',
  0x0010: 'CS04B Method B Unjoin',
  0x0012: 'CS06 Activate Firmware',
  0x0013: 'CS07 Read Device Join Details',
  0x0014: 'CS10a Read ZigBee Device Event Log',
  0x0015: 'CS11 Clear ZigBee Device Event Log',
  0x0018: 'CS14 Device Addition To / Removal From HAN Whitelist Alerts',
  0x0019: 'ECS01a Set Tariff and Price on ESME',
  0x001a: 'ECS02 Set ESME Payment Mode to Credit',
  0x001b: 'ECS03 Set ESME Payment Mode to Prepayment',
  0x001c: 'ECS04a Adjust Meter Balance on the ESME',
  0x001d: 'ECS05 Reset Tariff Block Counter Matrix',
  0x001e: 'ECS07 Manage Debt on the ESME',
  0x001f: 'ECS08 Update Prepayment Configuration on ESME',
  0x0020: 'ECS09 Activate Emergency Credit Remotely on ESME',
  0x0021: 'ECS10 Send Message to ESME',
  0x0022: 'ECS12 Set Change of Tenancy date on ESME',
  0x0023: 'ECS14 Disable Privacy PIN Protection on ESME',
  0x0024: 'ECS15a Clear ESME Event Log',
  0x0025: 'ECS16 Write Supplier Contact Details on ESME',
  0x0026: 'ECS17a Read ESME Energy Registers (Export Energy)',
  0x0027: 'ECS17b Read ESME Energy Registers (Import Energy)',
  0x0028: 'ECS17c Read ESME Energy Registers (Power)',
  0x0029: 'ECS17d Read ESME Energy Register (TOU)',
  0x002a: 'ECS17e Read ESME Energy Register (TOU with Blocks)',
  0x002b: 'ECS18a Read Maximum Demand Registers (export)',
  0x002c: 'ECS18b Read Maximum Demand Registers (import)',
  0x002d: 'ECS19 Read ESME Prepayment Registers',
  0x002e: 'ECS20a Read ESME Billing Data Log (payment based debt payments)',
  0x002f:
    'ECS20b Read ESME Billing Data Log (change of mode / tariff triggered exc export)',
  0x0030:
    'ECS20c Read ESME Billing Data Log (billing calendar triggered exc export)',
  0x0033: 'ECS21a Read Electricity Daily Read Log (exc export)',
  0x0034: 'ECS21b Read Electricity (Prepayment) Daily Read Log',
  0x0035: 'ECS21c Read Electricity Daily Read Log (export only)',
  0x0036: 'ECS22a Read Electricity Half Hour Profile Data (export)',
  0x0037: 'ECS22b Read Electricity Half Hour Profile Data (active import)',
  0x0038: 'ECS22c Read Electricity Half Hour Profile Data (reactive import)',
  0x0039: 'ECS23 Read Voltage Operational Data',
  0x003a: 'ECS24 Read ESME Tariff Data',
  0x003b: 'ECS26a Read ESME Configuration Data Prepayment',
  0x003c: 'ECS26b Read ESME Configuration Voltage Data',
  0x003d:
    'ECS26c Read ESME Configuration Data Device Information (randomisation)',
  0x003e:
    'ECS26d Read ESME Configuration Data Device Information (Billing Calendar)',
  0x003f:
    'ECS26e Read ESME Configuration Data Device Information (device identity exc MPAN)',
  0x0040:
    'ECS26f Read ESME Configuration Data Device Information (instantaneous power thresholds)',
  0x0042: 'ECS27 Read ESME Load Limit Data',
  0x0043: 'ECS28a Set Load Limit Configurations - General Settings',
  0x0044: 'ECS28b Set Load Limit Configuration Counter Reset',
  0x0045: 'ECS29a Set Voltage Configurations on ESME',
  0x0046: 'ECS30 Set Billing Calendar on the ESME',
  0x0047: 'ECS34 Set Instantaneous Power Threshold Configuration',
  0x0048: 'ECS35a Read ESME Event Log',
  0x0049: 'ECS35b Read ESME Security Log',
  0x004a: 'ECS37 Set Maximum Demand Configurable Time Period',
  0x004b: 'ECS38 Update Randomised Offset Limit',
  0x004c: 'ECS39a Set MPAN Value on the ESME',
  0x004d: 'ECS39b Set Export MPAN Value on the ESME',
  0x004e: 'ECS40 Read MPAN Value on the ESME',
  0x004f: 'ECS42 Remotely Close the Load Switch on the ESME',
  0x0050: 'ECS43 Remotely Open the Load Switch on the ESME',
  0x0051: 'ECS44 Arm Load Switch in ESME',
  0x0052: 'ECS45 Read Status of Load Switch in the ESME',
  0x0053: 'ECS46a Set HC ALCS or ALCS Labels in ESME',
  0x0054:
    'ECS46c Set HC ALCS and ALCS configuration in ESME (excluding labels)',
  0x0055: 'ECS47 Set or Reset HC ALCS or ALCS State',
  0x0058: 'ECS50 Send CIN to ESME',
  0x0059: 'ECS52 Read ESME/Comms Hub Firmware Version',
  0x005a: 'ECS57 Reset ESME Maximum Demand Registers',
  0x005e: 'ECS61c Read Boost Button Data from ESME',
  0x005f: 'ECS62 Set ALCS and Boost Button Association',
  0x0060: 'ECS66 Read ESME Daily Consumption Log',
  0x0061: 'ECS68 ESME Critical Sensitive Alert (Billing Data Log)',
  0x0062: 'ECS70 Set Clock on ESME',
  0x0067: 'ECS80 Supply Outage Restore Alert from ESME',
  0x0068: 'ECS81 Set Supply Tamper State on ESME',
  0x0069: 'ECS82 Read Meter Balance for ESME',
  0x006b: 'GCS01a Set Tariff and Price on GSME',
  0x006c: 'GCS02 Set GSME Payment Mode to Credit',
  0x006d: 'GCS03 Set GSME Payment Mode to Prepayment',
  0x006e: 'GCS04 Manage Debt on the GSME',
  0x006f: 'GCS05 Update Prepayment Configurations on GSME',
  0x0070: 'GCS06 Activate Emergency Credit Remotely on GSME',
  0x0071: 'GCS07 Send Message to GSME',
  0x0072: 'GCS09 Set Change of Tenancy date on GPF',
  0x0073: 'GCS11 Disable Privacy PIN Protection on GSME',
  0x0074: 'GCS13a Read GSME Consumption Register',
  0x0075: 'GCS14 Read GSME Prepayment Registers',
  0x0076: 'GCS15c Read GSME Billing Data Log (billing calendar triggered)',
  0x0077: 'GCS16a Read GSME Daily Read Log',
  0x0078: 'GCS17 Read GSME Profile Data Log',
  0x0079: 'GCS18 Read Gas Network Data Log',
  0x007b: 'GCS21a Read Gas Configuration Data Device Information',
  0x007c: 'GCS23 Set CV and Conversion Factor Value(s) on the GSME',
  0x007d:
    'GCS24 Set Uncontrolled Gas Flow Rate and Supply Tamper State on the GSME',
  0x007e: 'GCS25 Set Billing Calendar on the GSME',
  0x007f: 'GCS28 Set Clock on GSME',
  0x0080: 'GCS31 Start Network Data Log on GSME',
  0x0081: 'GCS32 Remotely close the valve in the GSME',
  0x0082: 'GCS33 Read GSME Valve Status',
  0x0083: 'GCS36 Send CIN to GSME',
  0x0084: 'GCS38 Read GSME Firmware Version',
  0x0085: 'GCS39 Arm Valve in GSME',
  0x0086: 'GCS40a Adjust Prepayment Mode Meter Balance on the GSME',
  0x0087: 'GCS41 Set MPRN Value on the GSME',
  0x0088: 'GCS44 Write Contact Details on GSME',
  0x0089: 'GCS46 Read MPRN on the GSME',
  0x008b: 'GCS53 Push Billing Data Log as an Alert',
  0x008c: 'GCS59 Restore GPF Device Log',
  0x008d: 'GCS60 Read Meter Balance for GSME',
  0x0090: 'PCS02 Activate Emergency Credit on GSME from PPMID',
  0x0092: 'ECS26i Read Configuration Data Device Information (CHF identity)',
  0x0093: 'ECS35c Read CHF Event Log',
  0x0094: 'ECS35d Read CHF Security Log',
  0x0096: 'GCS16b Read GSME Daily Read log(s) (prepayment)',
  0x0097: 'CS01b Apply Prepayment Top Up to a GSME',
  0x009b: 'PCS01 Apply Prepayment Top Up to a GSME using PPMID',
  0x009d:
    'GCS21d Read GSME Configuration Data Device Information (BillingCalendar)',
  0x009e:
    'GCS21e Read GSME/GPF Configuration Data Device Information (device identity)',
  0x009f: 'GCS21f Read GSME Tariff Data',
  0x00a0: 'GCS61 Read Gas Daily Consumption Log',
  0x00a1: 'CS10b Read ZigBee Device Security Log',
  0x00a2: 'ECS01b Set Price on ESME',
  0x00a3: 'GCS01b Set Price on GSME',
  0x00ab: 'CS03A2 Method A Join (non Meter)',
  0x00ac: 'ECS25a Set Alert Behaviours - ESME - Supplier',
  0x00ad: 'GCS20 Set Alert Behaviours - GSME',
  0x00ae: 'ECS29b Set Voltage Configurations on ESME - 3ph',
  0x00af: 'CS03C Method C Join',
  0x00b0: 'ECS25b Set Alert Behaviours - ESME - Network Operator',
  0x00b2: 'GCS62 Backup GPF Device Log',
  0x00b3: 'ECS04b Reset Meter Balance on the ESME',
  0x00b4: 'GCS40b Reset Prepayment Mode Meter Balance on the GSME',
  0x00b5: 'GCS21b Read GSME Configuration Data Prepayment',
  0x00b6: 'GCS13c Read GSME Register (TOU)',
  0x00b7: 'ECS01c Set Tariff and Price on ESME secondary',
  0x00b8: 'GCS13b Read GSME Block Counters',
  0x00b9: 'ECS35e Read ESME Power Event Log',
  0x00ba: 'ECS35f Read ALCS Event Log',
  0x00bb: 'ECS61a Read HC ALCS and ALCS Data from ESME',
  0x00bc: 'ECS23b Read Voltage Operational Data - 3 Phase',
  0x00bd: 'ECS24b Read ESME Tariff Data - second element',
  0x00be:
    'ECS26j Read ESME Configuration Data Device Information (Payment Mode)',
  0x00bf:
    'GCS21j Read GSME Configuration Data Device Information (Payment Mode)',
  0x00c0: 'GCS40c Adjust Credit Mode Meter Balance on the GSME',
  0x00c1: 'ECS15c Clear ALCS Event Log',
  0x00c2: 'GCS40d Reset Credit Mode Meter Balance on the GSME',
  0x00c3:
    'GCS15b Read GSME Billing Data Log (change of mode / tariff triggered)',
  0x00c4: 'GCS15d Read GSME Billing Data Log (payment-based debt payments)',
  0x00c5: 'GCS15e Read GSME Billing Data Log (prepayment credits)',
  0x00c6: 'ECS26k Read ESME Configuration Voltage Data - 3 phase',
  0x00c7: 'ECS01d Set Price on ESME secondary',
  0x00c9: 'ECS20d Read ESME Billing Data Log (prepayment credits)',
  0x00ca: 'Futured Dated Firmware Activation Alert',
  0x00cb: 'Futured Dated Update Security Credentials Alert',
  0x00cc: 'Future Dated Execution Of Instruction Alert (DLMS COSEM)',
  0x00cd: 'Future Dated Execution Of Instruction Alert (GBZ)',
  0x00ce: 'Firmware Distribution Receipt Alert (ESME)',
  0x00cf: 'Firmware Distribution Receipt Alert (GSME)',
  0x00d1: 'ECS29c Set Voltage Configurations on ESME without counter reset',
  0x00d2:
    'ECS29d Set Voltage Configurations on polyphase ESME without counter reset',
  0x00d3: 'ECS29e Reset RMS Voltage Counters on ESME',
  0x00d4: 'ECS29f Reset RMS Voltage Counters on polyphase ESME',
  0x00d5: 'Failure to Deliver Remote Party Message to ESME Alert',
  0x00d7: 'ECS30a Set Billing Calendar on the ESME - all periodicities',
  0x00d8: 'GCS25a Set Billing Calendar on the GSME - all periodicities',
  0x00d9:
    'ECS26l Read ESME Configuration Data Device Information (Billing Calendar - all periodicities)',
  0x00da:
    'GCS21k Read GSME Configuration Data Device Information (BillingCalendar - all periodicities)',
  0x00db: 'ECS48 Configure daily resetting of Tariff Block Counter Matrix',
  0x00de: 'ECS08a Update Prepayment Configuration on ESME',
  0x00ea: 'ECS25a1 Set Event Behaviours - ESME to HAN Device - Supplier',
  0x00eb: 'ECS25a2 Set Event Behaviours - ESME audible alarm - Supplier',
  0x00ec: 'ECS25a3 Set Event Behaviours - ESME logging - Supplier',
  0x00ed: 'ECS25b3 Set Event Behaviours - ESME logging - Network Operator',
  0x00ee:
    'ECS25r1 Read non-critical event and alert behaviours - ESME - Supplier',
  0x00ef:
    'ECS25r2 Read non-critical event and alert behaviours - ESME - Network Operator',
  0x00f0: 'Meter Integrity Issue Warning Alert - ESME',
  0x00f1:
    'GCS20r Read non-critical event and alert behaviours - GSME - Supplier',
  0x00f2: 'Meter Integrity Issue Warning Alert - GSME',
  0x00f9:
    'ECS26m Read ESME Configuration Data Device Information (identity,  type and supply tamper state)',
  0x00fa:
    'ECS26n Read CHF Configuration Data Device Information (CH identity and type)',
  0x00fb:
    'GCS21m Read GSME Configuration Data Device Information (identity, type and supply tamper / depletion state)',
  0x00fc:
    'GCS24a Set Uncontrolled Gas Flow Rate and Supply Tamper State on the GSME (SMETS4)',
  0x00fd: 'ECS35g Read ALCS Event Log',
  0x00fe: 'CCS07 Read CHF Device Logs',
  0x0100: 'CS02b Update Security Credentials (rootBySupplier)',
  0x0101: 'CS02b Update Security Credentials (rootByWanProvider)',
  0x0102: 'CS02b Update Security Credentials (supplierBySupplier)',
  0x0103:
    'CS02b Update Security Credentials (networkOperatorByNetworkOperator)',
  0x0104: 'CS02b Update Security Credentials (accessControlBrokerByACB)',
  0x0105: 'CS02b Update Security Credentials (wanProviderByWanProvider)',
  0x0106: 'CS02b Update Security Credentials (transCoSByTransCoS)',
  0x0107: 'CS02b Update Security Credentials (supplierByTransCoS)',
  0x0108: 'CS02b Update Security Credentials (anyExceptAbnormalRootByRecovery)',
  0x0109: 'CS02b Update Security Credentials (anyByContingency)',
  0x010a: 'DBCH01 Read CHF Sub GHz Channel',
  0x010b: 'DBCH02 Read CHF Sub GHz Channel Log',
  0x010c: 'DBCH03 Read CHF Sub GHz Configuration',
  0x010d: 'DBCH04 Set CHF Sub GHz Configuration',
  0x010e: 'DBCH05 Request CHF Sub GHz Channel Scan',
  0x010f: 'CCS06 Read CHF device log and check HAN communications',
  0x0110: 'DBCH06 Limited Duty Cycle Action Taken Sub GHz Alert',
  0x0111: 'DBCH07 Sub GHz Sub GHz Channel Changed Sub GHz Alert',
  0x0112:
    'DBCH08 Sub GHz Channel Scan Request Assessment Outcome Sub GHz Alert',
  0x0113: 'DBCH09 Sub GHz Configuration Changed Sub GHz Alert',
  0x0114: 'DBCH10 Message Discarded Due to Duty Cycle Management Sub GHz Alert',
  0x0115: 'DBCH11 No More Sub GHz Device Capacity Sub GHz Alert',
  0x0116: 'PECS01 Apply Prepayment Top Up to an ESME using PPMID',
  0x0117: 'PECS02 Activate Emergency Credit on ESME from PPMID',
  0x0118: 'PECS03 Request to Enable ESME Supply from PPMID',
  0x0119:
    'HECS01 Request Control of a HAN Connected Auxiliary Load Control Switch from HCALCS',
  0x0128: 'CCS08 Firmware Transfer Alert',
  0x0129: 'CS08 Read PPMID/HCALCS Firmware Version',
  0x1000: 'Generic Critical Alert',
  0x1001: 'Generic Non Critical Alert',
}

export const alertCodes: Record<number, string> = {
  0x8002:
    'Average RMS Voltage above Average RMS Over Voltage Threshold (current value above threshold; previous value below threshold)',
  0x8003:
    'Average RMS Voltage above Average RMS Over Voltage Threshold  on Phase 1 (current value above threshold; previous value below threshold)',
  0x8004:
    'Average RMS Voltage above Average RMS Over Voltage Threshold  on Phase 2 (current value above threshold; previous value below threshold)',
  0x8005:
    'Average RMS Voltage above Average RMS Over Voltage Threshold  on Phase 3 (current value above threshold; previous value below threshold)',
  0x8006:
    'Average RMS Voltage below Average RMS Under Voltage Threshold (current value below threshold; previous value above threshold)',
  0x8007:
    'Average RMS Voltage below Average RMS Under Voltage Threshold on Phase 1 (current value below threshold; previous value above threshold)',
  0x8008:
    'Average RMS Voltage below Average RMS Under Voltage Threshold on Phase 2 (current value below threshold; previous value above threshold)',
  0x8009:
    'Average RMS Voltage below Average RMS Under Voltage Threshold on Phase 3 (current value below threshold; previous value above threshold)',
  0x8010: 'Over Current',
  0x8011: 'Over Current L1',
  0x8016: 'Over Current L2',
  0x8013: 'Over Current L3',
  0x8014: 'Power Factor Threshold Below',
  0x8015: 'Power Factor Threshold Ok',
  0x8020:
    'RMS Voltage above Extreme Over Voltage Threshold (voltage rises above for longer than the configurable period)',
  0x8021:
    'RMS Voltage above Extreme Over Voltage Threshold on Phase 1 (voltage rises above for longer than the configurable period)',
  0x8022:
    'RMS Voltage above Extreme Over Voltage Threshold on Phase 2 (voltage rises above for longer than the configurable period)',
  0x8023:
    'RMS Voltage above Extreme Over Voltage Threshold on Phase 3 (voltage rises above for longer than the configurable period)',
  0x8024:
    'RMS Voltage above Voltage Swell Threshold (voltage rises above for longer than the configurable period)',
  0x8025:
    'RMS Voltage above Voltage Swell Threshold on Phase 1 (voltage rises above for longer than the configurable period)',
  0x8026:
    'RMS Voltage above Voltage Swell Threshold on Phase 2 (voltage rises above for longer than the configurable period)',
  0x8027:
    'RMS Voltage above Voltage Swell Threshold on Phase 3 (voltage rises above for longer than the configurable period)',
  0x8028:
    'RMS Voltage below Extreme Under Voltage Threshold (voltage falls below for longer than the configurable period)',
  0x8029:
    'RMS Voltage below Extreme Under Voltage Threshold on Phase 1 (voltage falls below for longer than the configurable period)',
  0x802a:
    'RMS Voltage below Extreme Under Voltage Threshold on Phase 2 (voltage falls below for longer than the configurable period)',
  0x802b:
    'RMS Voltage below Extreme Under Voltage Threshold on Phase 3 (voltage falls below for longer than the configurable period)',
  0x802c:
    'RMS Voltage below Voltage Sag Threshold (voltage falls below for longer than the configurable period)',
  0x802d:
    'RMS Voltage below Voltage Sag Threshold on Phase 1 (voltage falls below for longer than the configurable period)',
  0x802e:
    'RMS Voltage below Voltage Sag Threshold on Phase 2 (voltage falls below for longer than the configurable period)',
  0x802f:
    'RMS Voltage below Voltage Sag Threshold on Phase 3 (voltage falls below for longer than the configurable period)',
  0x8071: 'GPF Device Log Changed',
  0x8085:
    'Average RMS Voltage below Average RMS Over Voltage Threshold (current value below threshold; previous value above threshold)',
  0x8086:
    'Average RMS Voltage below Average RMS Over Voltage Threshold on Phase 1 (current value below threshold; previous value above threshold)',
  0x8087:
    'Average RMS Voltage below Average RMS Over Voltage Threshold on Phase 2 (current value below threshold; previous value above threshold)',
  0x8088:
    'Average RMS Voltage below Average RMS Over Voltage Threshold on Phase 3 (current value below threshold; previous value above threshold)',
  0x8089:
    'Average RMS Voltage above Average RMS Under Voltage Threshold (current value above threshold; previous value below threshold)',
  0x808a:
    'Average RMS Voltage above Average RMS Under Voltage Threshold on Phase 1 (current value above threshold; previous value below threshold)',
  0x808b:
    'Average RMS Voltage above Average RMS Under Voltage Threshold on Phase 2 (current value above threshold; previous value below threshold)',
  0x808c:
    'Average RMS Voltage above Average RMS Under Voltage Threshold on Phase 3 (current value above threshold; previous value below threshold)',
  0x808d:
    'RMS Voltage above Extreme Over Voltage Threshold (voltage returns below for longer than the configurable period)',
  0x808e:
    'RMS Voltage above Extreme Over Voltage Threshold on Phase 1 (voltage returns below for longer than the configurable period)',
  0x808f:
    'RMS Voltage above Extreme Over Voltage Threshold on Phase 2 (voltage returns below for longer than the configurable period)',
  0x8090:
    'RMS Voltage above Extreme Over Voltage Threshold on Phase 3 (voltage returns below for longer than the configurable period)',
  0x8091:
    'RMS Voltage above Voltage Swell Threshold (voltage returns below for longer than the configurable period)',
  0x8092:
    'RMS Voltage above Voltage Swell Threshold on Phase 1 (voltage returns below for longer than the configurable period)',
  0x8093:
    'RMS Voltage above Voltage Swell Threshold on Phase 2 (voltage returns below for longer than the configurable period)',
  0x8094:
    'RMS Voltage above Voltage Swell Threshold on Phase 3 (voltage returns below for longer than the configurable period)',
  0x8095:
    'RMS Voltage below Extreme Under Voltage Threshold (voltage returns above for longer than the configurable period)',
  0x8096:
    'RMS Voltage below Extreme Under Voltage Threshold on Phase 1 (voltage returns above for longer than the configurable period)',
  0x8097:
    'RMS Voltage below Extreme Under Voltage Threshold on Phase 2 (voltage returns above for longer than the configurable period)',
  0x8098:
    'RMS Voltage below Extreme Under Voltage Threshold on Phase 3 (voltage returns above for longer than the configurable period)',
  0x8099:
    'RMS Voltage below Voltage Sag Threshold (voltage returns above for longer than the configurable period)',
  0x809a:
    'RMS Voltage below Voltage Sag Threshold on Phase 1 (voltage returns above for longer than the configurable period)',
  0x809b:
    'RMS Voltage below Voltage Sag Threshold on Phase 2 (voltage returns above for longer than the configurable period)',
  0x809c:
    'RMS Voltage below Voltage Sag Threshold on Phase 3 (voltage returns above for longer than the configurable period)',
  0x810d: 'Combined Credit Below Low Credit Threshold (prepayment mode)',
  0x810e: 'Credit Added Locally',
  0x8119: 'Emergency Credit Has Become Available (prepayment mode)',
  0x8154: 'Immediate HAN Interface Command Received and Successfully Actioned',
  0x8155:
    'Immediate HAN Interface Command Received but not Successfully Actioned',
  0x8168: 'Supply Disabled then Armed - Activate Emergency Credit triggered',
  0x8183: 'Device joined SMHAN',
  0x8184: 'Valve tested',
  0x819d: 'GSME Command Not Retrieved',
  0x819e: 'Tap Off Message Response or Alert Failure',
  0x81a0: 'Smart Meter Integrity Issue - Warning',
  0x81a1: 'Battery Cover Closed',
  0x81a2: 'CH Connected to ESME',
  0x81a3: 'CH Disconnected from ESME',
  0x81a4: 'Close Tunnel Command Rejected',
  0x81a5: 'Communication From Local Port (e.g. Optical)',
  0x81a6: 'Customer Acknowledged Message on HAN Device',
  0x81a7: 'Debt Collection Completed - Time Debt 1',
  0x81a8: 'Debt Collection Completed - Time Debt 2',
  0x81a9: 'Debt Collection Completed - Payment Debt',
  0x81aa: 'Emergency Credit Exhausted',
  0x81ab: 'Emergency Credit Activated',
  0x81ac: 'Error Measurement Fault',
  0x81ad: 'Error Metrology Firmware Verification Failure',
  0x81ae: 'Error Non Volatile Memory',
  0x81af: 'Error Program Execution',
  0x81b0: 'Error Program Storage',
  0x81b1: 'Error RAM',
  0x81b2: 'Error Unexpected Hardware Reset',
  0x81b3: 'Error Watchdog ',
  0x81b4: 'Excess Gas Flow Beyond Meter Capacity',
  0x81b5: 'Flow Sensor Detects Air in Gas Flow',
  0x81b6: 'Flow Sensor Detects Reverse Flow of Gas',
  0x81b7: 'Incorrect phase sequencing',
  0x81b8: 'Incorrect Polarity',
  0x81b9: 'Meter Cover Closed',
  0x81ba: 'Request Tunnel Command Rejected',
  0x81bb: 'Reverse Current',
  0x81bc: 'Strong Magnetic Field Removed',
  0x81bd: 'Supply Connect Failure (Valve or Load Switch)',
  0x81be: 'Supply Disabled Then Locked - Supply Tamper State Cause',
  0x81bf: 'Supply Disabled Then Armed - Uncontrolled Gas Flow Rate',
  0x81c0: 'Supply Disconnect Failure (Valve or Load Switch)',
  0x81c1: 'Terminal Cover Closed',
  0x81c2: 'Tilt Tamper Ended',
  0x81c3: 'Tilt Tamper',
  0x81c4: 'UTRN Manual Entry Suspended',
  0x81c5: 'UTRN rejected as locked out',
  0x81c6: 'Clock not adjusted (outside tolerance)',
  0x8f01: 'Active Power Import above Load Limit Threshold',
  0x8f0a: 'Billing Data Log Updated',
  0x8f0c: 'Clock not adjusted (adjustment greater than 10 seconds)',
  0x8f0f: 'Credit Below Disablement Threshold (prepayment mode)',
  0x8f12: 'CHF Device Log Changed',
  0x8f1b: 'Firmware Verification Failed At Power On',
  0x8f1c: 'Firmware Verification Failed',
  0x8f1d: 'GSME Power Supply Loss',
  0x8f1e: 'Integrity check of content or format of command failed',
  0x8f1f: 'Low Battery Capacity',
  0x8f20: 'Limited Duty Cycle Action Taken',
  0x8f21: 'Duty Cycle fallen below Normal-Limited Duty Cycle Threshold',
  0x8f22: 'Critical Duty Cycle Action Taken',
  0x8f23: 'Duty Cycle fallen below Limited-Critical Duty Cycle Threshold',
  0x8f24: 'Regulated Duty Cycle Action Taken',
  0x8f25: 'Duty Cycle fallen below Critical-Regulated Duty Cycle Threshold',
  0x8f26: 'Sub GHz Channel Changed',
  0x8f27: 'Sub GHz Channel Scan initiated',
  0x8f28: 'Sub GHz Channel Scan Request Assessment Outcome',
  0x8f29: 'Three Lost GSME Searches Failed',
  0x8f2a: 'Sub GHz Configuration Changed',
  0x8f2b: 'Sub GHz Channel not changed due to Frequency Agility Parameters',
  0x8f2c: 'Message Discarded Due to Duty Cycle Management',
  0x8f2d: 'No More Sub GHz Device Capacity',
  0x8f30: 'Source Does not have Authority for Command',
  0x8f32: 'Supply Armed',
  0x8f33: 'Supply Disabled then Armed - Load Limit triggered',
  0x8f34:
    'Supply Enabled after Load Limit Restoration Period (Load Limit triggered)',
  0x8f35: 'Supply Outage Restored',
  0x8f36: 'Supply Outage Restored - Outage >= 3 minutes',
  0x8f37: 'Supply Outage Restored on Phase 1',
  0x8f38: 'Supply Outage Restored on Phase 1 Restored - Outage >= 3 minutes',
  0x8f39: 'Supply Outage Restored on Phase 2 Restored',
  0x8f3a: 'Supply Outage Restored on Phase 2 Restored - Outage >= 3 minutes',
  0x8f3b: 'Supply Outage Restored on Phase 3 Restored',
  0x8f3c: 'Supply Outage Restored on Phase 3 Restored - Outage >= 3 minutes',
  0x8f3d: 'Trusted Source Authentication Failure',
  0x8f3e: 'Unauthorised Communication Access attempted',
  0x8f3f: 'Unauthorised Physical Access - Tamper Detect',
  0x8f43: 'Change in the executing Firmware version',
  0x8145: 'Clock adjusted (within tolerance)',
  0x8f47:
    'Credit would cause Meter Balance to exceed  Maximum Meter Balance Threshold',
  0x8f48: 'Device joining failed',
  0x8f49: 'Device joining succeeded ',
  0x8f4a: 'Device Unjoining failed ',
  0x8f4b: 'Device Unjoining succeeded ',
  0x8f4c: "Device's own Digital Signing Certificate replacement failed",
  0x8f4d: "Device's own Digital Signing Certificate replacement succeeded",
  0x8f4e: "Device's own Key Agreement Certificate replacement failed",
  0x8f4f: "Device's own Key Agreement Certificate replacement succeeded",
  0x8f51: 'Duplicate UTRN entered',
  0x8f52: 'Event Log Cleared',
  0x8f53: 'Failed Authentication or Authorisation not covered by other codes',
  0x8f57: 'Supply interrupted',
  0x8f58: 'Supply interrupted on Phase 1',
  0x8f59: 'Supply interrupted on Phase 2',
  0x8f5a: 'Supply interrupted on Phase 3',
  0x8f5b: 'UTRN exceeds Maximum Credit Threshold',
  0x8f60:
    'Unusual numbers of malformed, out-of-order or unexpected Commands received',
  0x8161: 'User Interface Command Input and Successfully Actioned',
  0x8162: 'User Interface Command Input but not Successfully Actioned',
  0x8f63: 'UTRN not Authentic',
  0x8f64: 'UTRN not for this Device',
  0x8f66: 'Future-date HAN Interface Command Successfully Actioned',
  0x8f67: 'Future-date HAN Interface Command not Successfully Actioned',
  0x8f69: 'Device commissioned',
  0x8f70: 'Update Security Credentials ',
  0x8f72: 'Firmware Verification Successful',
  0x8f73: 'Unauthorised Physical Access - Battery Cover Removed',
  0x8f74: 'Unauthorised Physical Access - Meter Cover Removed',
  0x8f75: 'Unauthorised Physical Access - Strong Magnetic field',
  0x8f76: 'Unauthorised Physical Access - Terminal Cover Removed',
  0x8f77: 'Unauthorised Physical Access - Second Terminal Cover Removed',
  0x8f78: 'Unauthorised Physical Access - Other',
  0x8f82: 'Remaining Battery Capacity reset',
  0x8f83:
    'Disablement of Supply due to insufficient credit has been suspended ',
  0x8f84: 'Failure to Deliver Remote Party Message to ESME',
  0x8f89: 'Firmware transfer alert FAIL',
  0x8f8a: 'Firmware transfer alert SUCCESS',
  0x8f8b: 'Read Firmware version alert',
}

export const getAlertCodeName = (alertCode: number) => alertCodes[alertCode]

export function toHex(number: number, bits: number): string {
  if (bits <= 0 || bits % 4 !== 0) {
    throw new Error('bits out of range')
  }
  return (
    '0x' +
    (number + Math.pow(2, bits))
      .toString(16)
      .toUpperCase()
      .slice(-bits / 4)
  )
}

export function parseHexString(text: string): Slice {
  let bytes = new Uint8Array(text.length / 2)
  let length = 0
  for (let i = 0; i + 1 < text.length; i++) {
    let c = text.charCodeAt(i)
    if ((c > 47 && c < 58) || (c > 64 && c < 71) || (c > 96 && c < 103)) {
      c = text.charCodeAt(i + 1)
      if ((c > 47 && c < 58) || (c > 64 && c < 71) || (c > 96 && c < 103)) {
        bytes[length++] = parseInt(text.slice(i, i + 2), 16)
        i++
      }
    }
  }
  bytes = bytes.subarray(0, length)
  return { input: new Uint8ArrayWrapper(bytes), index: 0, end: length }
}

export function parseBase64String(text: string): Slice {
  const bytes = Buffer.from(text, 'base64')
  return { input: new Uint8ArrayWrapper(bytes), index: 0, end: bytes.length }
}

export function getBytes(x: Slice, n: number): Slice {
  const y = { input: x.input, index: x.index, end: x.index + n }
  x.index += n
  if (x.index > x.end) {
    throw new Error('slice out of bounds')
  }
  return y
}

export function getDecimalString(x: Slice) {
  const value64 = [0, 0]
  const fixedPoint = 1000000000000
  for (let i = x.index; i < x.end; i++) {
    const lsb = value64[0] * 256 + x.input.byte(i)
    const msb = value64[1] * 256 + Math.floor(lsb / fixedPoint)
    value64[0] = Math.floor(lsb % fixedPoint)
    value64[1] = msb
  }
  let decimalString = ''
  do {
    decimalString =
      String.fromCharCode(Math.floor(value64[0] % 10) + 0x30) + decimalString
    value64[0] =
      Math.floor(value64[0] / 10) +
      Math.floor(value64[1] % 10) * (fixedPoint / 10)
    value64[1] = Math.floor(value64[1] / 10)
  } while (value64[0] || value64[1])
  return decimalString
}
