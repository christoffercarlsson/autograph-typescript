import { concat, createFrom } from 'stedy/chunk'
import ephemeralDiffieHellman from '../crypto/diffie-hellman.js'
import kdf from '../crypto/kdf.js'
import readKeyShare from './read-key-share.js'

const deriveSharedSecret = async (
  diffieHellman,
  ourEphemeralPrivateKey,
  theirKeyShare,
  isInitiator
) => {
  const { publicKey, ephemeralPublicKey } = readKeyShare(theirKeyShare)
  const a = await diffieHellman(ephemeralPublicKey)
  const b = await ephemeralDiffieHellman(ourEphemeralPrivateKey, publicKey)
  return concat(isInitiator ? [a, b] : [b, a])
}

const deriveSecretKey = async (
  diffieHellman,
  context,
  ourEphemeralPrivateKey,
  theirKeyShare,
  isInitiator = true
) => {
  const sharedSecret = await deriveSharedSecret(
    diffieHellman,
    ourEphemeralPrivateKey,
    theirKeyShare,
    isInitiator === true
  )
  return kdf(
    sharedSecret,
    createFrom(Number.isInteger(context) ? [context] : context)
  )
}

export default deriveSecretKey
