import { createFrom, concat } from 'stedy/bytes'
import {
  exportKey,
  generateKeyPair as generateKeys,
  generateSignKeyPair as generateSignKeys
} from 'stedy'
import partial from './utils/partial'

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

export const generateKeyPair = async () => exportKeyPair(await generateKeys())

export const generateSignKeyPair = async () =>
  exportKeyPair(await generateSignKeys())

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
