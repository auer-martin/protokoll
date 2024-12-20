export enum FLOAT32_OPTIONS {
  NEVER = 0,
  ALWAYS = 1,
  DECIMAL_ROUND = 3,
  DECIMAL_FIT = 4,
}
export interface SizeLimitOptions {
  maxArraySize: number
  maxMapSize: number
  maxObjectSize: number
}
export interface Options {
  alwaysUseFloat?: boolean
  useFloat32?: FLOAT32_OPTIONS
  useRecords?: boolean
  structures?: {}[]
  structuredClone?: boolean
  mapsAsObjects?: boolean
  variableMapSize?: boolean
  copyBuffers?: boolean
  bundleStrings?: boolean
  useTimestamp32?: boolean
  largeBigIntToFloat?: boolean
  encodeUndefinedAsNil?: boolean
  maxSharedStructures?: number
  maxOwnStructures?: number
  useSelfDescribedHeader?: boolean
  useToJSON?: boolean
  keyMap?: {}
  shouldShareStructure?: (keys: string[]) => boolean
  getStructures?(): {}[]
  saveStructures?(structures: {}[]): boolean | undefined
  onInvalidDate?: () => any
  tagUint8Array?: boolean
  pack?: boolean
  sequential?: boolean
}
type ClassOf<T> = new (...args: any[]) => T
interface Extension<T, R> {
  Class: ClassOf<T>
  tag: number
  encode(value: T, encodeFn: (data: R) => Uint8Array): Buffer | Uint8Array
  decode(item: R): T
}
export class Decoder {
  constructor(options?: Options)
  decode(messagePack: Buffer | Uint8Array): any
  decodeMultiple(messagePack: Buffer | Uint8Array, forEach?: (value: any) => any): [] | undefined
}
export function setMaxLimits(options: SizeLimitOptions): void
export function decode(messagePack: Buffer | Uint8Array): any
export function decodeMultiple(messagePack: Buffer | Uint8Array, forEach?: (value: any) => any): [] | undefined
export function addExtension<T, R>(extension: Extension<T, R>): void
export function clearSource(): void
export function roundFloat32(float32Number: number): number
export let isNativeAccelerationEnabled: boolean

export class Encoder extends Decoder {
  encode(value: any): Buffer
}
export function encode(value: any): Buffer
export function encodeAsIterable(value: any): Iterable<Buffer | Blob | AsyncIterable<Buffer>>
export function encodeAsAsyncIterable(value: any): AsyncIterable<Buffer>

import { Transform } from 'node:stream'

export as namespace CBOR
export class DecoderStream extends Transform {
  constructor(options?: Options | { highWaterMark: number; emitClose: boolean; allowHalfOpen: boolean })
}
export class EncoderStream extends Transform {
  constructor(options?: Options | { highWaterMark: number; emitClose: boolean; allowHalfOpen: boolean })
}

export class Tag {
  constructor(value: any, tagNumber: number)
  value: any
  tag: number
}
