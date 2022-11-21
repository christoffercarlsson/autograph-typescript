import {
  exportKey,
  generateKeyPair as generateKeys,
  generateSignKeyPair as generateSignKeys
} from 'stedy'
import { createFrom, concat, Chunk } from 'stedy/bytes'
import partial from './utils/partial'

export type KeyPair = {
  publicKey: Chunk
  privateKey: Chunk
}

export type KeyShare = {
  ourKeyShare: Chunk
  ourEphemeralPrivateKey: Chunk
}

export type GenerateKeyShareFunction = () => Promise<KeyShare>

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
  const { publicKey, privateKey: ourEphemeralPrivateKey } =
    await generateKeyPair()
  const ourKeyShare = concat([
    createFrom(ourSignPublicKey),
    createFrom(ourPublicKey),
    publicKey
  ])
  return {
    ourKeyShare,
    ourEphemeralPrivateKey
  }
}

export const createGenerateKeyShare = (
  ourSignPublicKey: BufferSource,
  ourPublicKey: BufferSource
) =>
  partial(
    generateKeyShare,
    ourSignPublicKey,
    ourPublicKey
  ) as GenerateKeyShareFunction
