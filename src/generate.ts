import { createFrom, concat } from 'stedy/chunk'
import {
  CURVE_CURVE25519,
  exportKey,
  generateKeyPair as generateKeys,
  generateSignKeyPair as generateSignKeys
} from 'stedy/crypto'
import { partial } from 'stedy/util'

export type KeyPair = {
  publicKey: Uint8Array
  privateKey: Uint8Array
}

export type KeyShare = {
  keyShare: Uint8Array
  privateKey: Uint8Array
}

export type KeyShareFunction = () => Promise<KeyShare>

const exportKeyPair = async ({
  publicKey,
  privateKey
}: KeyPair): Promise<KeyPair> => ({
  publicKey: await exportKey(publicKey),
  privateKey: await exportKey(privateKey)
})

export const generateKeyPair = async () =>
  exportKeyPair(await generateKeys(CURVE_CURVE25519))

export const generateSignKeyPair = async () =>
  exportKeyPair(await generateSignKeys(CURVE_CURVE25519))

export const generateKeyShare = async (
  ourSignPublicKey: BufferSource,
  ourPublicKey: BufferSource
): Promise<KeyShare> => {
  const { publicKey, privateKey } = await generateKeyPair()
  const keyShare = concat([
    createFrom(ourSignPublicKey),
    createFrom(ourPublicKey),
    publicKey
  ])
  return { keyShare, privateKey }
}

export const createGenerateKeyShare = (
  ourSignPublicKey: BufferSource,
  ourPublicKey: BufferSource
) =>
  partial(generateKeyShare, ourSignPublicKey, ourPublicKey) as KeyShareFunction
