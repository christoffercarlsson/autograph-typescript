import {
  createIdentify,
  createProve,
  IdentifyFunction,
  ProveFunction
} from './authenticate'
import {
  CalculateSafetyNumberFunction,
  createCalculateSafetyNumber
} from './calculate-safety-number'
import { CertificationResult, CertifyFunction, createCertify } from './certify'
import { CONTEXT_INITIATOR, CONTEXT_RESPONDER } from './constants'
import createCertificate from './create-certificate'
import createDiffieHellman, {
  DiffieHellmanFunction
} from './create-diffie-hellman'
import createSign, { SignFunction } from './create-sign'
import createTrustedParties from './create-trusted-parties'
import {
  createGenerateKeyShare,
  generateKeyPair,
  generateSignKeyPair,
  KeyPair,
  KeyShare,
  GenerateKeyShareFunction
} from './generate'
import { createTrust, TrustFunction } from './trust'
import {
  createVerifySignature,
  VerifySignatureFunction
} from './verify-signature'
import {
  createVerifyOwnership,
  VerificationResult,
  VerifyOwnershipFunction
} from './verify'
import { Chunk, createFrom } from 'stedy/bytes'

export type Party = {
  calculateSafetyNumber: CalculateSafetyNumberFunction
  generateKeyShare: GenerateKeyShareFunction
  identify: IdentifyFunction
  prove: ProveFunction
  publicKey: Chunk
  signPublicKey: Chunk
}

export type Alice = Party & {
  verifySignature: VerifySignatureFunction
}

export type Bob = Party & {
  trust: TrustFunction
  verify: VerifyOwnershipFunction
}

export type Charlie = Party & {
  certify: CertifyFunction
  verify: VerifyOwnershipFunction
}

export type {
  CertificationResult,
  DiffieHellmanFunction,
  KeyPair,
  KeyShare,
  SignFunction,
  VerificationResult
}

const createParty = (signPublicKey: BufferSource, publicKey: BufferSource) => ({
  calculateSafetyNumber: createCalculateSafetyNumber(signPublicKey, publicKey),
  generateKeyShare: createGenerateKeyShare(signPublicKey, publicKey),
  publicKey: createFrom(publicKey),
  signPublicKey: createFrom(signPublicKey)
})

const createAlice = (
  signPublicKey: BufferSource,
  publicKey: BufferSource,
  sign: SignFunction,
  diffieHellman: DiffieHellmanFunction,
  trustedParties: BufferSource,
  trustThreshold: number,
  certificate?: BufferSource
): Alice => ({
  ...createParty(signPublicKey, publicKey),
  identify: createIdentify(sign, diffieHellman, CONTEXT_INITIATOR, certificate),
  prove: createProve(sign, diffieHellman, CONTEXT_INITIATOR),
  verifySignature: createVerifySignature(
    diffieHellman,
    trustedParties,
    trustThreshold
  )
})

const createBob = (
  signPublicKey: BufferSource,
  publicKey: BufferSource,
  sign: SignFunction,
  diffieHellman: DiffieHellmanFunction,
  trustedParties: BufferSource,
  trustThreshold: number,
  certificate?: BufferSource
): Bob => ({
  ...createParty(signPublicKey, publicKey),
  identify: createIdentify(sign, diffieHellman, CONTEXT_INITIATOR, certificate),
  prove: createProve(sign, diffieHellman, CONTEXT_INITIATOR),
  trust: createTrust(diffieHellman, trustedParties, trustThreshold),
  verify: createVerifyOwnership(diffieHellman, trustedParties, trustThreshold)
})

const createCharlie = (
  signPublicKey: BufferSource,
  publicKey: BufferSource,
  sign: SignFunction,
  diffieHellman: DiffieHellmanFunction,
  trustedParties: BufferSource,
  trustThreshold: number,
  certificate?: BufferSource
): Charlie => ({
  ...createParty(signPublicKey, publicKey),
  certify: createCertify(
    sign,
    diffieHellman,
    trustedParties,
    trustThreshold,
    certificate
  ),
  identify: createIdentify(sign, diffieHellman, CONTEXT_RESPONDER, certificate),
  prove: createProve(sign, diffieHellman, CONTEXT_RESPONDER),
  verify: createVerifyOwnership(diffieHellman, trustedParties, trustThreshold)
})

export {
  createAlice,
  createBob,
  createCertificate,
  createCharlie,
  createDiffieHellman,
  createSign,
  createTrustedParties,
  generateKeyPair,
  generateSignKeyPair
}
