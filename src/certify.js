import { concat } from 'stedy/chunk'
import { authenticate } from './authenticate.js'
import { CONTEXT_INITIATOR, CONTEXT_RESPONDER } from './constants.js'
import { verify } from './verify.js'

const createResult = (
  identityKey,
  data = null,
  authentication = null,
  error = null
) => ({
  error: error || null,
  identityKey,
  data,
  authentication,
  verified: error === null
})

const createErrorResult = (
  error,
  theirIdentityKey = null,
  data = null,
  authentication = null
) => createResult(theirIdentityKey, data, authentication, error)

const certify = async (
  sign,
  diffieHellman,
  trustedParties,
  trustThreshold,
  ourCertificate,
  ourKeyShare,
  ourEphemeralPrivateKey,
  theirKeyShare,
  ciphertext
) => {
  try {
    const {
      data,
      error: verificationError,
      identityKey: theirIdentityKey
    } = await verify(
      diffieHellman,
      CONTEXT_INITIATOR,
      trustedParties,
      trustThreshold,
      ourKeyShare,
      ourEphemeralPrivateKey,
      theirKeyShare,
      ciphertext,
      true
    )
    if (verificationError) {
      return createErrorResult(verificationError, theirIdentityKey, data)
    }
    const signature = await sign(concat([data, theirIdentityKey]))
    const authentication = await authenticate(
      sign,
      diffieHellman,
      CONTEXT_RESPONDER,
      signature,
      ourCertificate,
      ourEphemeralPrivateKey,
      theirKeyShare
    )
    return createResult(theirIdentityKey, data, authentication)
  } catch (error) {
    return createErrorResult(error)
  }
}

export default certify
