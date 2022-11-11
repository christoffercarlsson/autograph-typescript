import { concat, createFrom } from 'stedy/chunk'
import { partial } from 'stedy/util'
import { authenticate } from './authenticate'
import { CONTEXT_INITIATOR, CONTEXT_RESPONDER } from './constants'
import { DiffieHellmanFunction } from './create-diffie-hellman'
import { SignFunction } from './create-sign'
import {
  createResult as createVerificationResult,
  VerificationResult,
  verify
} from './verify'

export type CertificationResult = VerificationResult & {
  authentication?: Uint8Array
}

export type CertifyFunction = (
  ourKeyShare: BufferSource,
  ourEphemeralPrivateKey: BufferSource,
  theirKeyShare: BufferSource,
  ciphertext: BufferSource
) => Promise<CertificationResult>

const createResult = (
  identityKey: Uint8Array,
  data: Uint8Array,
  authentication?: Uint8Array,
  error?: Error
): CertificationResult => {
  const result = createVerificationResult(identityKey, data, error)
  return {
    ...result,
    authentication
  }
}

const createErrorResult = (
  error: Error,
  identityKey?: Uint8Array,
  data?: Uint8Array
) => createResult(identityKey, data, null, error)

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
