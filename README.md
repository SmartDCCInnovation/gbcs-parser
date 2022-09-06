# GBCS Parser

Tool based on [HenryGiraldo/gbcs-parser-js][gbcs-parser-js], which is a super
useful browser based [GBCS][gbcs] parser. It has been uplifted to use TypeScript
and output JSON instead of performing DOM manipulations. In addition, to allow
running from NodeJS the crypto API was exchanged for the NodeJS [Crypto
API][crypto].

The parser is aimed at being used with [DCC Boxed][boxed], so does not need full
coverage of GBCS. As such, support for GBT has been removed. It has been lightly
tested against `RTDS 4.5.0` (Reference Test Data Set). Further, the parser has
been tweaked to provide more slightly more structured parsed data as it returns
JSON instead of filling a HTML tabl.


## Usage

Please note, developed against `node 16` and makes use of its `crypto` api.

The library exposes a few high-level functions that are intended to be used
externally. This includes:

* `parseGbcsMessage`
* `minimizeMessage`
* `signGroupingHeader`

In addition, to use the `parseGbcsMessage` and `signGroupingHeader` functions a
key store needs to be provided. The makes available either digital signature or
key agreement certificates (as defined by GBCS). The key store is a simple
asynchronous callback which the user can implement (e.g. it could query
certificates from a [DCC&nbsp;Boxed][boxed] service). In the examples below, the
[dccboxed-keystore][keystore] project is used.

### Setup Key Store for DCC&nbsp;Boxed

The below code shims the interface provided by [dccboxed-keystore][keystore]
into the correct format for this project. It is intended to provide access to
default keys installed on DCC Boxed and query its SMKI interface for
certificates it does not have (e.g. device certificates). Below code
can be extended as needed.

```typescript
import { KeyObject } from 'node:crypto'
import { BoxedKeyStore } from '@smartdcc/dccboxed-keystore'

/**
 * used to filter certificates/keys that are not needed
 */
function removeNotBoxedEntries<T extends { role?: number; name?: string }>({
  role,
  name,
}: T): boolean {
  return (
    role !== 135 &&
    (name === undefined ||
      name.match(/Z1-[a-zA-Z0-9]+(?!PP)[a-zA-Z0-9]{2}-/) !== null)
  )
}

const keystore = await BoxedKeyStore.new(
    '1.2.3.4', /* ip address of dcc boxed */
)

/**
 * define callback
 */
export async function LocalKeyStore(
  eui: string | Uint8Array,
  type: 'KA' | 'DS',
  privateKey?: boolean
): Promise<KeyObject> {
  if (privateKey) {
    let results = await keyStore.query({
      eui,
      keyUsage:
        type === 'DS' ? KeyUsage.digitalSignature : KeyUsage.keyAgreement,
      lookup: 'privateKey',
    })
    results = (results ?? []).filter(removeNotBoxedEntries)
    if (results.length === 1) {
      return results[0].privateKey
    }
  } else {
    let results = await keyStore.query({
      eui,
      keyUsage:
        type === 'DS' ? KeyUsage.digitalSignature : KeyUsage.keyAgreement,
      lookup: 'certificate',
    })
    results = (results ?? []).filter(removeNotBoxedEntries)
    if (results.length === 1) {
      return results[0].certificate.publicKey
    }
  }
  throw new Error(
    `${privateKey ? 'private' : 'public'} key not found for ${eui} for ${type}`
  )
}
```

### Parse Message

```typescript
import { parseGbcsMessage, minimizeMessage } from '@smartdcc/gbcs-parser'
import { inspect } from 'node:util'

const parsed = await parseGbcsMessage(
  '3QAAAAAAAFURAAAAAN8JAgAAAYKDJi7hCLwzrAD++lU8CJCz1R8wAAACABIAWZCz1R8wAQAAAAABgoMmLUUR2iAmLuEAAAEJBAACAAABAQAACahvMaB+y9JJIHeL',
  LocalKeyStore
)
console.log(inspect(minimizeMessage(parsed), { colors: true, depth: 10 }))
```

The use of `minimizeMessage` removed redundant information from the output of
`parseGbcsMessage` which is used to keep the state of the parser.

This produces the following:

```javascript
{
  'MAC Header': {
    'General Ciphering': { hex: 'DD 00 00 00 00 00 00' },
    'Ciphered Service Length': { hex: '55', notes: '85' },
    'Security Header': { hex: '11 00 00 00 00' }
  },
  'Grouping Header': {
    'General Signing': { hex: 'DF 09' },
    'CRA Flag': { hex: '02', notes: 'Response' },
    'Originator Counter': { hex: '00 00 01 82 83 26 2E E1', notes: '1660057693921' },
    'Originator System Title': { hex: '08 BC 33 AC 00 FE FA 55 3C' },
    'Recipient System Title': { hex: '08 90 B3 D5 1F 30 00 00 02' },
    'Date Time': { hex: '00' },
    'Other Information Length': {
      hex: '12',
      notes: '18',
      children: {
        'Message Code': {
          hex: '00 59',
          notes: 'ECS52 Read ESME/Comms Hub Firmware Version'
        },
        'Supplementary Remote Party ID': { hex: '90 B3 D5 1F 30 01 00 00' },
        'Supplementary Remote Party Counter': { hex: '00 00 01 82 83 26 2D 45', notes: '1660057693509' }
      }
    },
    'Content Length': { hex: '11', notes: '17' }
  },
  Payload: {
    'DLMS Access Response': {
      hex: 'DA 20 26 2E E1 00 00',
      children: {
        'List of Access Response Data': {
          hex: '01',
          children: {
            '[0] Octet String': { hex: '09 04 00 02 00 00', notes: '00:02:00.00' }
          }
        },
        'List of Access Response Specification': {
          hex: '01',
          children: {
            '[0] Access Response Specification': {
              hex: '01',
              notes: 'Access Response Get [0]',
              children: { 'Data Access Result': { hex: '00', notes: 'Success' } }
            }
          }
        }
      }
    }
  },
  Signature: { 'Signature Length': { hex: '00', notes: '0' } },
  MAC: { MAC: { hex: '09 A8 6F 31 A0 7E CB D2 49 20 77 8B' } }
}
```

The interested reader is suggested to compare this with the output of
[HenryGiraldo/gbcs-parser-js][gbcs-parser-js].

### Sign Message

The library also provides support for signing GBCS pre-commands. The current
implementation is aligned with DCC&nbsp;Boxed. To sign a message, use the following:

```typescript
import { signGroupingHeader } from '@smartdcc/gbcs-parser'

console.log(await signGroupingHeader(
  '90-b3-d5-1f-30-01-00-00',
  '3wkBAAABgoNAlH0IkLPVHzABAAAIvDOs//76VT0AAgBibNkgQJR9AAUCAAgAAAEAAP8JAwAIAAABAAD/BQMACAAAAQAA/wQBAAgAAAEAAP8CAQAIAAABAAD/BAUWBQIDCQz///////////+AAP8JDAfeDB//FzsKAIAA/wkMB98BAf8AAAoAgAD/DwAAAA==',
  LocalKeyStore,
))
```

This could produce the following:

```
3wkBAAABgoNAlH0IkLPVHzABAAAIvDOs//76VT0AAgBibNkgQJR9AAUCAAgAAAEAAP8JAwAIAAABAAD/BQMACAAAAQAA/wQBAAgAAAEAAP8CAQAIAAABAAD/BAUWBQIDCQz///////////+AAP8JDAfeDB//FzsKAIAA/wkMB98BAf8AAAoAgAD/DwAAAECKdRM+cYyVimzkVv9VdaEneMRUTTtP8O8e0IPakREPLfqgx4CDHzYGmPSzhQ+3PxIz9v8hD3N4cv73SIv8p9Gx
```

## Other Info

Copyright 2022, Smart DCC Limited, All rights reserved. Project is licensed under GPLv3.

Also, copyright for the original work remains with
[HenryGiraldo/gbcs-parser-js][gbcs-parser-js].

[gbcs-parser-js]: https://github.com/HenryGiraldo/gbcs-parser-js "GitHub: GBCS Parser JS"
[crypto]: https://nodejs.org/docs/latest-v14.x/api/crypto.html "NodeJS Crypto API v14.x"
[gbcs]: https://smartenergycodecompany.co.uk/the-smart-energy-code-2/ "Smart Energy Code"
[boxed]: https://www.smartdcc.co.uk/our-smart-network/network-products-services/dcc-boxed/ "DCC Boxed"
[keystore]: https://github.com/SmartDCCInnovation/dccboxed-keystore "GitHub: DCCBoxed KeyStore"