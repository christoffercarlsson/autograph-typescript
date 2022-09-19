import { concat, createFrom } from 'stedy/chunk'
import { CONTEXT_RESPONDER } from './constants.js'
import verifyData from './crypto/verify.js'
import readKeyShare from './utils/read-key-share.js'
import { verify } from './verify.js'

const createResult = (identityKey, signature = null, error = null) => ({
  error: error || null,
  identityKey,
  signature,
  verified: error === null
})

const createErrorResult = (error, identityKey = null, signature = null) =>
  createResult(identityKey, signature, error)

const verifySignature = async (
  diffieHellman,
  trustedParties,
  trustThreshold,
  ourData,
  ourKeyShare,
  ourEphemeralPrivateKey,
  theirKeyShare,
  ciphertext
) => {
  try {
    const {
      data: signature,
      error: verificationError,
      identityKey
    } = await verify(
      diffieHellman,
      CONTEXT_RESPONDER,
      trustedParties,
      trustThreshold,
      ourKeyShare,
      ourEphemeralPrivateKey,
      theirKeyShare,
      ciphertext,
      true
    )
    if (verificationError) {
      return createErrorResult(verificationError, identityKey)
    }
    const { signPublicKey: ourIdentityKey } = readKeyShare(ourKeyShare)
    const verified = await verifyData(
      concat([createFrom(ourData), ourIdentityKey]),
      identityKey,
      signature
    )
    if (!verified) {
      return createErrorResult(new Error('Signature verification failed'))
    }
    return createResult(identityKey, signature)
  } catch (error) {
    return createErrorResult(error)
  }
}

export default verifySignature
