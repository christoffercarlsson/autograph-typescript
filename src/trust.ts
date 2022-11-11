import { partial } from 'stedy/util'
import { CONTEXT_RESPONDER } from './constants'
import { DiffieHellmanFunction } from './create-diffie-hellman'
import {
  createErrorResult,
  createResult,
  VerificationResult,
  verify
} from './verify'

export type TrustFunction = (
  ourKeyShare: BufferSource,
  ourEphemeralPrivateKey: BufferSource,
  theirKeyShare: BufferSource,
  ciphertext: BufferSource
) => Promise<VerificationResult>

export const trust = async (
  diffieHellman: DiffieHellmanFunction,
  trustedParties: BufferSource,
  trustThreshold: number,
  ourKeyShare: BufferSource,
  ourEphemeralPrivateKey: BufferSource,
  theirKeyShare: BufferSource,
  ciphertext: BufferSource
) => {
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
}

export const createTrust = (
  diffieHellman: DiffieHellmanFunction,
  trustedParties: BufferSource,
  trustThreshold: number
) =>
  partial(trust, diffieHellman, trustedParties, trustThreshold) as TrustFunction
