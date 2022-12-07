import * as util from '../src/util'

describe('alerts', () => {
  test('getAlertCodeName defined', () => {
    expect(util['getAlertCodeName']).toBeDefined()
  })

  test('getAlertCodeName lookup', () => {
    expect(util['getAlertCodeName'](0x81c4)).toBe('UTRN Manual Entry Suspended')
  })
})

describe('toHex', () => {
  test('no bits error', () => {
    expect(() => util.toHex(0, 0)).toThrowError('bits out of range')
  })

  test('bits not multiple of 4', () => {
    expect(() => util.toHex(0, 3)).toThrowError('bits out of range')
  })

  describe('nominal', () => {
    const testCase: {
      n: number
      b: number
      s: string
    }[] = [
      { n: 0, b: 4, s: '0x0' },
      { n: 0, b: 8, s: '0x00' },
      { n: 1, b: 16, s: '0x0001' },
      { n: 0xbeef, b: 16, s: '0xBEEF' },
    ]
    testCase.forEach((tc) => {
      test(tc.s, () => {
        expect(util.toHex(tc.n, tc.b)).toBe(tc.s)
      })
    })
  })
})

describe('parseHexString', () => {
  test('empty', () => {
    const slice = util.parseHexString('')
    expect(slice.input).toBeDefined()
    expect(slice.input.length).toBe(0)
    expect(slice.index).toBe(0)
    expect(slice.end).toBe(0)
  })

  test('nibble', () => {
    const slice = util.parseHexString('a')
    expect(slice.input).toBeDefined()
    expect(slice.input.length).toBe(0)
    expect(slice.index).toBe(0)
    expect(slice.end).toBe(0)
  })

  test('byte', () => {
    const slice = util.parseHexString('a5')
    expect(slice.input).toBeDefined()
    expect(slice.input.length).toBe(1)
    expect(slice.input.buffer[0]).toBe(0xa5)
    expect(slice.index).toBe(0)
    expect(slice.end).toBe(1)
  })

  test('byte-uppercase', () => {
    const slice = util.parseHexString('A5')
    expect(slice.input).toBeDefined()
    expect(slice.input.length).toBe(1)
    expect(slice.input.buffer[0]).toBe(0xa5)
    expect(slice.index).toBe(0)
    expect(slice.end).toBe(1)
  })

  test('multi-byte', () => {
    const slice = util.parseHexString('BE eFCaFE 45')
    expect(slice.input).toBeDefined()
    expect(slice.input.length).toBe(5)
    expect(slice.input.buffer[0]).toBe(0xbe)
    expect(slice.input.buffer[1]).toBe(0xef)
    expect(slice.input.buffer[2]).toBe(0xca)
    expect(slice.input.buffer[3]).toBe(0xfe)
    expect(slice.input.buffer[4]).toBe(0x45)
    expect(slice.index).toBe(0)
    expect(slice.end).toBe(5)
  })

  test('whitespace', () => {
    const slice = util.parseHexString('BE      eF Ca\n  \t FE\t45')
    expect(slice.input).toBeDefined()
    expect(slice.input.length).toBe(5)
    expect(slice.input.buffer[0]).toBe(0xbe)
    expect(slice.input.buffer[1]).toBe(0xef)
    expect(slice.input.buffer[2]).toBe(0xca)
    expect(slice.input.buffer[3]).toBe(0xfe)
    expect(slice.input.buffer[4]).toBe(0x45)
    expect(slice.index).toBe(0)
    expect(slice.end).toBe(5)
  })

  test('whitespace-2', () => {
    const slice = util.parseHexString('B E      e F Ca\n  \t F   \tE\t4\n5')
    expect(slice.input).toBeDefined()
    expect(slice.input.length).toBe(1)
    expect(slice.input.buffer[0]).toBe(0xca)
    expect(slice.index).toBe(0)
    expect(slice.end).toBe(1)
  })
})

describe('parseHexString', () => {
  test('empty', () => {
    const slice = util.parseBase64String('')
    expect(slice.input).toBeDefined()
    expect(slice.input.length).toBe(0)
    expect(slice.index).toBe(0)
    expect(slice.end).toBe(0)
  })

  test('nominal', () => {
    const slice = util.parseBase64String('aGVsbG8gd29ybGQ=')
    expect(slice.input).toBeDefined()
    expect(slice.input.length).toBe(11)
    expect(slice.input.toString()).toBe('hello world')
    expect(slice.index).toBe(0)
    expect(slice.end).toBe(11)
  })

  test('whitespace', () => {
    const slice = util.parseBase64String('aGVs bG8g d29y bGQ=')
    expect(slice.input).toBeDefined()
    expect(slice.input.length).toBe(11)
    expect(slice.input.toString()).toBe('hello world')
    expect(slice.index).toBe(0)
    expect(slice.end).toBe(11)
  })

  test('no-padding', () => {
    const slice = util.parseBase64String('aGVsbG8gd29ybGQ')
    expect(slice.input).toBeDefined()
    expect(slice.input.length).toBe(11)
    expect(slice.input.toString()).toBe('hello world')
    expect(slice.index).toBe(0)
    expect(slice.end).toBe(11)
  })

  test('whitespace-savage', () => {
    const slice = util.parseBase64String('a G V s\nbG8g\td2  9y bG\nQ')
    expect(slice.input).toBeDefined()
    expect(slice.input.length).toBe(11)
    expect(slice.input.toString()).toBe('hello world')
    expect(slice.index).toBe(0)
    expect(slice.end).toBe(11)
  })
})

describe('getBytes', () => {
  let x: util.Slice

  beforeEach(() => {
    x = util.parseBase64String('aGVsbG8gd29ybGQ=')
  })

  test('no-bytes', () => {
    const original = Object.assign({}, x)
    const slice = util.getBytes(x, 0)

    expect(x.input).toBe(original.input)
    expect(x.index).toBe(original.index)
    expect(x.end).toBe(original.end)

    expect(slice.input).toBe(original.input)
    expect(slice.index).toBe(original.index)
    expect(slice.end).toBe(original.index)
  })

  test('one-byte', () => {
    const original = Object.assign({}, x)
    const slice = util.getBytes(x, 1)

    expect(x.input).toBe(original.input)
    expect(x.index).toBe(original.index + 1)
    expect(x.end).toBe(original.end)

    expect(slice.input).toBe(original.input)
    expect(slice.index).toBe(original.index)
    expect(slice.end).toBe(original.index + 1)
  })

  test('two-bytes-not-beginning', () => {
    util.getBytes(x, 2)
    const original = Object.assign({}, x)
    expect(original.index).toBe(2)

    const slice = util.getBytes(x, 2)

    expect(x.input).toBe(original.input)
    expect(x.index).toBe(original.index + 2)
    expect(x.end).toBe(original.end)

    expect(slice.input).toBe(original.input)
    expect(slice.index).toBe(original.index)
    expect(slice.end).toBe(original.index + 2)
  })

  test('no-bytes-not-beginning', () => {
    util.getBytes(x, 2)
    const original = Object.assign({}, x)
    expect(original.index).toBe(2)

    const slice = util.getBytes(x, 0)

    expect(x.input).toBe(original.input)
    expect(x.index).toBe(original.index)
    expect(x.end).toBe(original.end)

    expect(slice.input).toBe(original.input)
    expect(slice.index).toBe(original.index)
    expect(slice.end).toBe(original.index)
  })
})

describe('getDecimalString', () => {
  test('empty', () => {
    expect(util.getDecimalString(util.parseHexString(''))).toBe('0')
  })

  test('zero', () => {
    expect(util.getDecimalString(util.parseHexString('00'))).toBe('0')
  })

  test('one-byte', () => {
    expect(util.getDecimalString(util.parseHexString('f5'))).toBe(String(0xf5))
  })

  test('two-byte-low', () => {
    expect(util.getDecimalString(util.parseHexString('00f5'))).toBe(
      String(0xf5)
    )
  })

  test('two-byte', () => {
    expect(util.getDecimalString(util.parseHexString('07f5'))).toBe(
      String(0x7f5)
    )
  })

  test('four-byte', () => {
    expect(util.getDecimalString(util.parseHexString('beefcafe'))).toBe(
      String(0xbeefcafe)
    )
  })
})
