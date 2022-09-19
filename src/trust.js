import { CONTEXT_RESPONDER } from './constants.js'
import { verify } from './verify.js'

const createResult = (identityKey, error = null) => ({
  error: error || null,
  identityKey,
  verified: error === null
})

const createErrorResult = (error, identityKey = null) =>
  createResult(identityKey, error)

const trust = async (
  diffieHellman,
  trustedParties,
  trustThreshold,
  ourKeyShare,
  ourEphemeralPrivateKey,
  theirKeyShare,
  ciphertext
) => {
  try {
    const { error: verificationError, identityKey } = await verify(
      diffieHellman,
      CONTEXT_RESPONDER,
      trustedParties,
      trustThreshold,
      ourKeyShare,
      ourEphemeralPrivateKey,
      theirKeyShare,
      ciphertext
    )
    if (verificationError) {
      return createErrorResult(verificationError, identityKey)
    }
    return createResult(identityKey)
  } catch (error) {
    return createErrorResult(error)
  }
}

export default trust
