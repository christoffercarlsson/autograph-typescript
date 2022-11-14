import { concat, createFrom } from 'stedy/bytes'
import { DiffieHellmanFunction } from '../create-diffie-hellman'
import ephemeralDiffieHellman from '../crypto/diffie-hellman'
import kdf from '../crypto/kdf'
import readKeyShare from './read-key-share'

const deriveSharedSecret = async (
  diffieHellman: DiffieHellmanFunction,
  ourEphemeralPrivateKey: BufferSource,
  theirKeyShare: BufferSource,
  isInitiator: boolean
) => {
  const { publicKey, ephemeralPublicKey } = readKeyShare(theirKeyShare)
  const a = createFrom(await diffieHellman(ephemeralPublicKey))
  const b = await ephemeralDiffieHellman(ourEphemeralPrivateKey, publicKey)
  return concat(isInitiator ? [a, b] : [b, a])
}

const deriveSecretKey = async (
  diffieHellman: DiffieHellmanFunction,
  context: number,
  ourEphemeralPrivateKey: BufferSource,
  theirKeyShare: BufferSource,
  isInitiator: boolean
) => {
  const sharedSecret = await deriveSharedSecret(
    diffieHellman,
    ourEphemeralPrivateKey,
    theirKeyShare,
    isInitiator === true
  )
  return kdf(sharedSecret, context)
}

export default deriveSecretKey
