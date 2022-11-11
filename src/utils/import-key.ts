import { CURVE_CURVE25519, importKey } from 'stedy/crypto'

export const importPrivateKey = (key: BufferSource) =>
  importKey(CURVE_CURVE25519, false, false, key)

export const importPrivateSignKey = (key: BufferSource) =>
  importKey(CURVE_CURVE25519, true, false, key)

export const importPublicKey = (key: BufferSource) =>
  importKey(CURVE_CURVE25519, false, true, key)

export const importPublicSignKey = (key: BufferSource) =>
  importKey(CURVE_CURVE25519, true, true, key)
