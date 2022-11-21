import { Chunk, concat, createFrom } from 'stedy/bytes'
import { authenticate } from './authenticate'
import { CONTEXT_INITIATOR, CONTEXT_RESPONDER } from './constants'
import { DiffieHellmanFunction } from './create-diffie-hellman'
import { SignFunction } from './create-sign'
import partial from './utils/partial'
import {
  createResult as createVerificationResult,
  VerificationResult,
  verify
} from './verify'

export type CertificationResult = VerificationResult & {
  authentication?: Chunk
}

export type CertifyFunction = (
  ourKeyShare: BufferSource,
  ourEphemeralPrivateKey: BufferSource,
  theirKeyShare: BufferSource,
  ciphertext: BufferSource
) => Promise<CertificationResult>

const createResult = (
  identityKey: Chunk,
  data: Chunk,
  authentication?: Chunk,
  error?: Error
): CertificationResult => {
  const result = createVerificationResult(identityKey, data, error)
  return {
    ...result,
    authentication
  }
}

const createErrorResult = (error: Error, identityKey?: Chunk, data?: Chunk) =>
  createResult(identityKey, data, null, error)

export const certify = async (
  sign: SignFunction,
  diffieHellman: DiffieHellmanFunction,
  trustedParties: BufferSource,
  trustThreshold: number,
  ourCertificate: BufferSource,
  ourKeyShare: BufferSource,
  ourEphemeralPrivateKey: BufferSource,
  theirKeyShare: BufferSource,
  ciphertext: BufferSource
) => {
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
}

export const createCertify = (
  sign: SignFunction,
  diffieHellman: DiffieHellmanFunction,
  trustedParties: BufferSource,
  trustThreshold: number,
  ourCertificate?: BufferSource
) =>
  partial(
    certify,
    sign,
    diffieHellman,
    trustedParties,
    trustThreshold,
    ourCertificate || createFrom()
  ) as CertifyFunction
