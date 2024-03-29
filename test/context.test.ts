import * as context from '../src/context'
import { getBytes, parseHexString, Slice } from '../src/util'

describe('putSeparator', () => {
  let ctx: context.Context
  beforeEach(() => {
    ctx = {
      lookupKey: () => {
        throw Error('not implemented')
      },
      output: {},
      current: [],
      decryptionList: [],
    }
  })

  test('initial', () => {
    context.putSeparator(ctx, 'heading')
    expect(ctx.output).toMatchObject({
      heading: {},
    })
  })

  test('subsequent', () => {
    context.putSeparator(ctx, 'heading-1')
    context.putSeparator(ctx, 'heading-2')
    expect(ctx.output).toMatchObject({
      'heading-1': {
        children: {},
      },
      'heading-2': {
        children: {},
      },
    })
  })

  test('subsequent-same', () => {
    context.putSeparator(ctx, 'heading')
    expect(() => context.putSeparator(ctx, 'heading')).toThrow()
  })
})

describe('putBytes', () => {
  let ctx: context.Context
  let slice: Slice
  beforeEach(() => {
    slice = parseHexString('00112233445566778899aabbccddeeff')
    ctx = {
      lookupKey: () => {
        throw Error('not implemented')
      },
      output: {},
      current: [],
      decryptionList: [],
    }
    context.putSeparator(ctx, 'root')
  })

  test('nominal', () => {
    context.putBytes(ctx, 'data', slice)

    expect(ctx.output).toMatchObject({
      root: {
        children: {
          data: { hex: '00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF' },
        },
      },
    })
  })

  test('no-bytes', () => {
    context.putBytes(ctx, 'data', getBytes(slice, 0))

    expect(ctx.output).toMatchObject({
      root: {
        children: {
          data: { hex: '' },
        },
      },
    })
  })

  test('twice', () => {
    context.putBytes(ctx, 'data1', getBytes(slice, 8))
    context.putBytes(ctx, 'data2', slice)

    expect(ctx.output).toMatchObject({
      root: {
        children: {
          data1: { hex: '00 11 22 33 44 55 66 77' },
          data2: { hex: '88 99 AA BB CC DD EE FF' },
        },
      },
    })
  })

  test('nested', () => {
    context.putBytes(ctx, 'data1', getBytes(slice, 8))
    context.putBytes(ctx, ' data2', slice)

    expect(ctx.output).toMatchObject({
      root: {
        children: {
          data1: {
            hex: '00 11 22 33 44 55 66 77',
            children: {
              data2: { hex: '88 99 AA BB CC DD EE FF' },
            },
          },
        },
      },
    })
  })

  test('accidental-nesting', () => {
    expect(() => {
      context.putBytes(ctx, ' data1', getBytes(slice, 8))
    }).toThrow('incorrect nesting')
  })

  test('accidental-nesting-2', () => {
    context.putBytes(ctx, 'data1', getBytes(slice, 8))
    expect(() => {
      context.putBytes(ctx, '  data2', slice)
    }).toThrow('incorrect nesting')
  })

  test('twice-with-separator', () => {
    context.putBytes(ctx, 'data1', getBytes(slice, 8))
    context.putSeparator(ctx, 'root2')
    context.putBytes(ctx, 'data2', slice)

    expect(ctx.output).toMatchObject({
      root: {
        children: {
          data1: { hex: '00 11 22 33 44 55 66 77' },
        },
      },
      root2: {
        children: {
          data2: { hex: '88 99 AA BB CC DD EE FF' },
        },
      },
    })
  })
})

describe('putUnparsedBytes', () => {
  let slice: Slice
  beforeEach(() => {
    slice = parseHexString('00112233445566778899aabbccddeeff')
  })

  test('nominal', () => {
    getBytes(slice, 16)
    expect(() => {
      context.putUnparsedBytes(slice)
    }).not.toThrow()
  })

  test('fail', () => {
    getBytes(slice, 15)
    expect(() => {
      context.putUnparsedBytes(slice)
    }).toThrow('unexpected data')
  })
})

describe('minimizeItem', () => {
  test('flat', () => {
    const pi: context.ParsedItem = {
      depth: 3,
      type: 'ITEM',
      hex: '11 22 33',
    }
    expect(context.minimizeItem(pi)).toStrictEqual({
      hex: '11 22 33',
    })
  })

  test('flat-notes-undefined', () => {
    const pi: context.ParsedItem = {
      depth: 3,
      type: 'ITEM',
      hex: '11 22 33',
      notes: undefined,
    }
    expect(context.minimizeItem(pi)).toStrictEqual({
      hex: '11 22 33',
    })
  })

  test('flat-notes', () => {
    const pi: context.ParsedItem = {
      depth: 3,
      type: 'ITEM',
      hex: '11 22 33',
      notes: 'a note',
    }
    expect(context.minimizeItem(pi)).toStrictEqual({
      hex: '11 22 33',
      notes: 'a note',
    })
  })

  test('flat-empty-children', () => {
    const pi: context.ParsedItem = {
      depth: 3,
      type: 'ITEM',
      hex: '11 22 33',
      children: {},
    }
    expect(context.minimizeItem(pi)).toStrictEqual({
      hex: '11 22 33',
    })
  })

  test('recursive', () => {
    const pi: context.ParsedItem = {
      depth: 3,
      type: 'ITEM',
      hex: '11 22 33',
      children: {
        key1: {
          depth: 3,
          type: 'ITEM',
          hex: 'aa',
          notes: "aa's notes",
        },
        key2: {
          depth: 3,
          type: 'ITEM',
          hex: 'bb',
        },
      },
    }
    expect(context.minimizeItem(pi)).toStrictEqual({
      hex: '11 22 33',
      children: {
        key1: {
          hex: 'aa',
          notes: "aa's notes",
        },
        key2: {
          hex: 'bb',
        },
      },
    })
  })
})

describe('minimizeBlock', () => {
  test('flat', () => {
    const pb: context.ParsedBlock = {
      depth: 3,
      type: 'SEPARATOR',
      children: {},
    }
    expect(context.minimizeBlock(pb)).toStrictEqual({})
  })

  test('nominal', () => {
    const pb: context.ParsedBlock = {
      depth: 0,
      type: 'SEPARATOR',
      children: {
        key1: {
          depth: 1,
          type: 'ITEM',
          hex: '00 11',
        },
        key2: {
          depth: 1,
          type: 'ITEM',
          hex: '22 33',
        },
      },
    }
    expect(context.minimizeBlock(pb)).toStrictEqual({
      key1: {
        hex: '00 11',
      },
      key2: {
        hex: '22 33',
      },
    })
  })
})

describe('minimizeMessage', () => {
  test('flat', () => {
    const pm: context.ParsedMessage = {}
    expect(context.minimizeMessage(pm)).toStrictEqual({})
  })

  test('nominal', () => {
    const pm: context.ParsedMessage = {
      block1: {
        depth: 0,
        type: 'SEPARATOR',
        children: {
          key1: {
            depth: 1,
            type: 'ITEM',
            hex: '00 11',
          },
          key2: {
            depth: 1,
            type: 'ITEM',
            hex: '22 33',
          },
        },
      },
      block2: {
        depth: 0,
        type: 'SEPARATOR',
        children: {
          key3: {
            depth: 1,
            type: 'ITEM',
            hex: '44 55 66',
          },
          key4: {
            depth: 1,
            type: 'ITEM',
            hex: '66 77 88 99',
            notes: 'notes',
          },
        },
      },
    }
    expect(context.minimizeMessage(pm)).toStrictEqual({
      block1: {
        key1: {
          hex: '00 11',
        },
        key2: {
          hex: '22 33',
        },
      },
      block2: {
        key3: {
          hex: '44 55 66',
        },
        key4: {
          hex: '66 77 88 99',
          notes: 'notes',
        },
      },
    })
  })
})
