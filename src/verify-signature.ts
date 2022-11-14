import { concat, createFrom } from 'stedy/bytes'
import { CONTEXT_RESPONDER } from './constants'
import { DiffieHellmanFunction } from './create-diffie-hellman'
import verifyData from './crypto/verify'
import partial from './utils/partial'
import readKeyShare from './utils/read-key-share'
import {
  createErrorResult,
  createResult,
  VerificationResult,
  verify
} from './verify'

export type VerifySignatureFunction = (
  ourData: BufferSource,
  ourKeyShare: BufferSource,
  ourEphemeralPrivateKey: BufferSource,
  theirKeyShare: BufferSource,
  ciphertext: BufferSource
) => Promise<VerificationResult>

export const verifySignature = async (
  diffieHellman: DiffieHellmanFunction,
  trustedParties: BufferSource,
  trustThreshold: number,
  ourData: BufferSource,
  ourKeyShare: BufferSource,
  ourEphemeralPrivateKey: BufferSource,
  theirKeyShare: BufferSource,
  ciphertext: BufferSource
) => {
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
}

export const createVerifySignature = (
  diffieHellman: DiffieHellmanFunction,
  trustedParties: BufferSource,
  trustThreshold: number
) =>
  partial(
    verifySignature,
    diffieHellman,
    trustedParties,
    trustThreshold
  ) as VerifySignatureFunction
