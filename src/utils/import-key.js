import { CURVE_CURVE25519, importKey } from 'stedy/crypto'

export const importPrivateKey = (key) =>
  importKey(CURVE_CURVE25519, false, false, key)

export const importPrivateSignKey = (key) =>
  importKey(CURVE_CURVE25519, true, false, key)

export const importPublicKey = (key) =>
  importKey(CURVE_CURVE25519, false, true, key)

export const importPublicSignKey = (key) =>
  importKey(CURVE_CURVE25519, true, true, key)
