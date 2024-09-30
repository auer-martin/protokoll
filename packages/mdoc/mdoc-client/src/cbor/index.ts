import type { Options } from 'cbor-x';
import { addExtension, Encoder } from 'cbor-x';

export { DataItem } from './data-item.js';

export { addExtension } from 'cbor-x';

const encoderDefaults: Options = {
  tagUint8Array: false,
  useRecords: false,
  mapsAsObjects: false,
  // @ts-ignore
  useTag259ForMaps: false,
};

addExtension({
  Class: Date,
  tag: 1004,
  encode: (instance: Date, encode) => {
    const str = instance.toISOString().split('T')[0];
    return encode(str);
  },
  decode: (val: any): object => {
    return new Date(val);
  },
});

export const cborDecode = (
  input: Uint8Array,
  options: Options = encoderDefaults
): any => {
  const params = { ...encoderDefaults, ...options };
  const enc = new Encoder(params);
  return enc.decode(input);
};

export const cborEncode = (
  obj: unknown,
  options: Options = encoderDefaults
): Uint8Array => {
  const params = { ...encoderDefaults, ...options };
  const enc = new Encoder(params);
  return enc.encode(obj);
};