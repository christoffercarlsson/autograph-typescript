import { Chunk, concat, createFrom } from 'stedy/bytes'
import {
  CONTEXT_INITIATOR,
  CONTEXT_RESPONDER,
  PUBLIC_KEY_SIZE,
  SIGNATURE_SIZE
} from './constants'
import { DiffieHellmanFunction } from './create-diffie-hellman'
import decrypt from './crypto/decrypt'
import verifyData from './crypto/verify'
import deriveSecretKey from './utils/derive-secret-key'
import partial from './utils/partial'
import readKeyShare from './utils/read-key-share'

export type VerificationResult = {
  data?: Chunk
  error?: Error
  identityKey?: Chunk
  verified: boolean
}

export type VerifyOwnershipFunction = (
  ourKeyShare: BufferSource,
  ourEphemeralPrivateKey: BufferSource,
  theirKeyShare: BufferSource,
  ciphertext: BufferSource
) => Promise<VerificationResult>

type TrustParamaterResult = {
  threshold: number
  identityKeys: Chunk[]
}

type TrustedSignatureEntry = {
  identityKey: Chunk
  signature: Chunk
}

/* istanbul ignore next */
const getError = (error: unknown) => {
  if (error === undefined || error === null) {
    return null
  }
  if (error instanceof Error) {
    return error
  }
  if (typeof error === 'string') {
    return new Error(error)
  }
  return new Error('Unknown error')
}

export const createResult = (
  identityKey?: Chunk,
  data?: Chunk,
  err?: unknown
): VerificationResult => {
  const error = getError(err)
  return {
    data: data || null,
    error,
    identityKey: identityKey || null,
    verified: error === null
  }
}

export const createErrorResult = (
  error: unknown,
  identityKey: Chunk = null,
  data: Chunk = null
) => createResult(identityKey, data, error)

const readAuthentication = (
  ourKeyShare: BufferSource,
  theirKeyShare: BufferSource,
  message: BufferSource
) => {
  const { ephemeralPublicKey: ourEphemeralPublicKey } =
    readKeyShare(ourKeyShare)
  const { signPublicKey: theirIdentityKey } = readKeyShare(theirKeyShare)
  const [signature, next] = createFrom(message).read(SIGNATURE_SIZE)
  const [certificate, data] = next
    .subarray(2)
    .read(next.readUint16BE() * (PUBLIC_KEY_SIZE + SIGNATURE_SIZE))
  return {
    ourEphemeralPublicKey,
    theirIdentityKey,
    signature,
    certificate,
    data
  }
}

const calculateTrustParameters = (
  trustThreshold: number,
  trustedParties: BufferSource,
  theirIdentityKey: Chunk
) => {
  const identityKeys = createFrom(trustedParties).split(PUBLIC_KEY_SIZE)
  return identityKeys.reduce(
    (result: TrustParamaterResult, identityKey) => {
      if (identityKey.equals(theirIdentityKey)) {
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

const isTrustedParty = (identityKeys: Chunk[], identityKey: Chunk) =>
  identityKeys.length > 0 && identityKeys.some((key) => key.equals(identityKey))

const findTrustedSignatures = (identityKeys: Chunk[], certificate: Chunk) => {
  const entries = certificate
    .split(PUBLIC_KEY_SIZE + SIGNATURE_SIZE)
    .map((entry) => entry.read(PUBLIC_KEY_SIZE))
  return entries.reduce(
    (trustedEntries: TrustedSignatureEntry[], [identityKey, signature]) => {
      if (isTrustedParty(identityKeys, identityKey)) {
        return [...trustedEntries, { identityKey, signature }]
      }
      return trustedEntries
    },
    []
  )
}

const verifyTrust = async (
  trustThreshold: number,
  trustedParties: BufferSource,
  theirIdentityKey: Chunk,
  certificate: Chunk,
  theirData: Chunk
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
  signatureVerified: boolean,
  trustVerified: boolean,
  theirIdentityKey: Chunk,
  data: Chunk
) => {
  if (!signatureVerified) {
    return createErrorResult(
      new Error('Signature verification failed'),
      theirIdentityKey,
      data
    )
  }
  if (!trustVerified) {
    return createErrorResult(
      new Error('Trust verification failed'),
      theirIdentityKey,
      data
    )
  }
  return createResult(theirIdentityKey, data)
}

const verifyAuthentication = async (
  trustThreshold: number,
  trustedParties: BufferSource,
  ourKeyShare: BufferSource,
  theirKeyShare: BufferSource,
  authentication: BufferSource,
  omitDataInTrustVerification: boolean
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
  diffieHellman: DiffieHellmanFunction,
  context: number,
  trustedParties: BufferSource,
  trustThreshold: number,
  ourKeyShare: BufferSource,
  ourEphemeralPrivateKey: BufferSource,
  theirKeyShare: BufferSource,
  ciphertext: BufferSource,
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
    return verifyAuthentication(
      trustThreshold,
      trustedParties,
      ourKeyShare,
      theirKeyShare,
      authentication,
      omitDataInTrustVerification === true
    )
  } catch (error) {
    /* istanbul ignore next */
    return createErrorResult(error)
  }
}

export const verifyOwnership = (
  diffieHellman: DiffieHellmanFunction,
  trustedParties: BufferSource,
  trustThreshold: number,
  ourKeyShare: BufferSource,
  ourEphemeralPrivateKey: BufferSource,
  theirKeyShare: BufferSource,
  ciphertext: BufferSource
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

export const createVerifyOwnership = (
  diffieHellman: DiffieHellmanFunction,
  trustedParties: BufferSource,
  trustThreshold: number
) =>
  partial(
    verifyOwnership,
    diffieHellman,
    trustedParties,
    trustThreshold
  ) as VerifyOwnershipFunction
