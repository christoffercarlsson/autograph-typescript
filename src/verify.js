import {
  concat,
  createFrom,
  equals,
  read,
  readUint16BE,
  split
} from 'stedy/chunk'
import {
  CONTEXT_INITIATOR,
  CONTEXT_RESPONDER,
  PUBLIC_KEY_SIZE,
  SIGNATURE_SIZE
} from './constants.js'
import decrypt from './crypto/decrypt.js'
import verifyData from './crypto/verify.js'
import deriveSecretKey from './utils/derive-secret-key.js'
import readKeyShare from './utils/read-key-share.js'

const createResult = (identityKey, data, error = null) => ({
  data,
  error: error || null,
  identityKey,
  verified: error === null
})

const createErrorResult = (error, identityKey = null, data = null) =>
  createResult(identityKey, data, error)

const readAuthentication = (ourKeyShare, theirKeyShare, message) => {
  const { ephemeralPublicKey: ourEphemeralPublicKey } =
    readKeyShare(ourKeyShare)
  const { signPublicKey: theirIdentityKey } = readKeyShare(theirKeyShare)
  const [signature, next] = read(message, SIGNATURE_SIZE)
  const [certificate, data] = read(
    next.subarray(2),
    readUint16BE(next) * (PUBLIC_KEY_SIZE + SIGNATURE_SIZE)
  )
  return {
    ourEphemeralPublicKey,
    theirIdentityKey,
    signature,
    certificate,
    data
  }
}

const calculateTrustParameters = (
  trustThreshold,
  trustedParties,
  theirIdentityKey
) => {
  const identityKeys = split(trustedParties, PUBLIC_KEY_SIZE)
  return identityKeys.reduce(
    (result, identityKey) => {
      if (equals(identityKey, theirIdentityKey)) {
        return { ...result, threshold: Math.max(result.threshold - 1, 0) }
      }
      return { ...result, identityKeys: [...result.identityKeys, identityKey] }
    },
    {
      threshold:
        Number.isInteger(trustThreshold) && trustThreshold > 0
          ? trustThreshold
          : 0,
      identityKeys: []
    }
  )
}

const isTrustedParty = (identityKeys, identityKey) =>
  identityKeys.length > 0 &&
  identityKeys.some((key) => equals(key, identityKey))

const findTrustedSignatures = (identityKeys, certificate) => {
  const entries = split(certificate, PUBLIC_KEY_SIZE + SIGNATURE_SIZE).map(
    (entry) => read(entry, PUBLIC_KEY_SIZE)
  )
  return entries.reduce((trustedEntries, [identityKey, signature]) => {
    if (isTrustedParty(identityKeys, identityKey)) {
      return [...trustedEntries, { identityKey, signature }]
    }
    return trustedEntries
  }, [])
}

const verifyTrust = async (
  trustThreshold,
  trustedParties,
  theirIdentityKey,
  certificate,
  theirData
) => {
  const { threshold, identityKeys } = calculateTrustParameters(
    trustThreshold,
    trustedParties,
    theirIdentityKey
  )
  const entries = findTrustedSignatures(identityKeys, certificate)
  if (entries.length < threshold) {
    return false
  }
  const data = concat([theirData, theirIdentityKey])
  const results = await Promise.all(
    entries.map(({ identityKey, signature }) =>
      verifyData(data, identityKey, signature)
    )
  )
  return results.every((result) => result === true)
}

const verifyResult = (
  signatureVerified,
  trustVerified,
  theirIdentityKey,
  data
) => {
  try {
    if (!signatureVerified) {
      throw new Error('Signature verification failed')
    }
    if (!trustVerified) {
      throw new Error('Trust verification failed')
    }
    return createResult(theirIdentityKey, data)
  } catch (error) {
    return createErrorResult(error, theirIdentityKey, data)
  }
}

const verifyAuthentication = async (
  trustThreshold,
  trustedParties,
  ourKeyShare,
  theirKeyShare,
  authentication,
  omitDataInTrustVerification
) => {
  const {
    ourEphemeralPublicKey,
    theirIdentityKey,
    signature,
    certificate,
    data
  } = readAuthentication(ourKeyShare, theirKeyShare, authentication)
  const signatureVerified = await verifyData(
    concat([data, ourEphemeralPublicKey]),
    theirIdentityKey,
    signature
  )
  const trustVerified = await verifyTrust(
    trustThreshold,
    trustedParties,
    theirIdentityKey,
    certificate,
    omitDataInTrustVerification ? createFrom() : data
  )
  return verifyResult(
    signatureVerified === true,
    trustVerified === true,
    theirIdentityKey,
    data
  )
}

export const verify = async (
  diffieHellman,
  context,
  trustedParties,
  trustThreshold,
  ourKeyShare,
  ourEphemeralPrivateKey,
  theirKeyShare,
  ciphertext,
  omitDataInTrustVerification = false
) => {
  try {
    const key = await deriveSecretKey(
      diffieHellman,
      context,
      ourEphemeralPrivateKey,
      theirKeyShare,
      context === CONTEXT_RESPONDER
    )
    const authentication = await decrypt(key, ciphertext)
    const result = await verifyAuthentication(
      trustThreshold,
      trustedParties,
      ourKeyShare,
      theirKeyShare,
      authentication,
      omitDataInTrustVerification === true
    )
    return result
  } catch (error) {
    return createErrorResult(error)
  }
}

export const verifyOwnership = (
  diffieHellman,
  trustedParties,
  trustThreshold,
  ourKeyShare,
  ourEphemeralPrivateKey,
  theirKeyShare,
  ciphertext
) =>
  verify(
    diffieHellman,
    CONTEXT_INITIATOR,
    trustedParties,
    trustThreshold,
    ourKeyShare,
    ourEphemeralPrivateKey,
    theirKeyShare,
    ciphertext
  )
