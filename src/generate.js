import { concat } from 'stedy/chunk'
import {
  CURVE_CURVE25519,
  exportKey,
  generateKeyPair as generateKeys,
  generateSignKeyPair as generateSignKeys
} from 'stedy/crypto'

const exportKeyPair = async ({ publicKey, privateKey }) => ({
  publicKey: await exportKey(publicKey),
  privateKey: await exportKey(privateKey)
})

export const generateKeyPair = async () =>
  exportKeyPair(await generateKeys(CURVE_CURVE25519))

export const generateSignKeyPair = async () =>
  exportKeyPair(await generateSignKeys(CURVE_CURVE25519))

export const generateKeyShare = async (ourSignPublicKey, ourPublicKey) => {
  const { publicKey, privateKey } = await generateKeyPair()
  const keyShare = concat([ourSignPublicKey, ourPublicKey, publicKey])
  return { keyShare, privateKey }
}
