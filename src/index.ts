import {
  createIdentify,
  createProve,
  identify,
  IdentifyFunction,
  prove,
  ProveFunction
} from './authenticate'
import {
  calculateSafetyNumber,
  CalculateSafetyNumberFunction,
  createCalculateSafetyNumber
} from './calculate-safety-number'
import {
  certify,
  CertificationResult,
  CertifyFunction,
  createCertify
} from './certify'
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
  generateKeyShare,
  generateSignKeyPair,
  KeyPair,
  KeyShare,
  KeyShareFunction
} from './generate'
import { createTrust, trust, TrustFunction } from './trust'
import {
  createVerifySignature,
  verifySignature,
  VerifySignatureFunction
} from './verify-signature'
import {
  createVerifyOwnership,
  verifyOwnership as verify,
  VerificationResult,
  VerifyOwnershipFunction
} from './verify'
import { createFrom } from 'stedy/chunk'

export type Alice = {
  calculateSafetyNumber: CalculateSafetyNumberFunction
  generateKeyShare: KeyShareFunction
  identify: IdentifyFunction
  prove: ProveFunction
  publicKey: Uint8Array
  signPublicKey: Uint8Array
  verifySignature: VerifySignatureFunction
}

export type Bob = {
  calculateSafetyNumber: CalculateSafetyNumberFunction
  generateKeyShare: KeyShareFunction
  identify: IdentifyFunction
  prove: ProveFunction
  publicKey: Uint8Array
  signPublicKey: Uint8Array
  trust: TrustFunction
  verify: VerifyOwnershipFunction
}

export type Charlie = {
  calculateSafetyNumber: CalculateSafetyNumberFunction
  certify: CertifyFunction
  generateKeyShare: KeyShareFunction
  identify: IdentifyFunction
  prove: ProveFunction
  publicKey: Uint8Array
  signPublicKey: Uint8Array
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

const createAlice = (
  signPublicKey: BufferSource,
  publicKey: BufferSource,
  sign: SignFunction,
  diffieHellman: DiffieHellmanFunction,
  trustedParties: BufferSource,
  trustThreshold: number,
  certificate?: BufferSource
): Alice => ({
  calculateSafetyNumber: createCalculateSafetyNumber(signPublicKey, publicKey),
  generateKeyShare: createGenerateKeyShare(signPublicKey, publicKey),
  identify: createIdentify(sign, diffieHellman, CONTEXT_INITIATOR, certificate),
  prove: createProve(sign, diffieHellman, CONTEXT_INITIATOR),
  publicKey: createFrom(publicKey),
  signPublicKey: createFrom(signPublicKey),
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
  calculateSafetyNumber: createCalculateSafetyNumber(signPublicKey, publicKey),
  generateKeyShare: createGenerateKeyShare(signPublicKey, publicKey),
  identify: createIdentify(sign, diffieHellman, CONTEXT_INITIATOR, certificate),
  prove: createProve(sign, diffieHellman, CONTEXT_INITIATOR),
  publicKey: createFrom(publicKey),
  signPublicKey: createFrom(signPublicKey),
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
  calculateSafetyNumber: createCalculateSafetyNumber(signPublicKey, publicKey),
  certify: createCertify(
    sign,
    diffieHellman,
    trustedParties,
    trustThreshold,
    certificate
  ),
  generateKeyShare: createGenerateKeyShare(signPublicKey, publicKey),
  identify: createIdentify(sign, diffieHellman, CONTEXT_RESPONDER, certificate),
  prove: createProve(sign, diffieHellman, CONTEXT_RESPONDER),
  publicKey: createFrom(publicKey),
  signPublicKey: createFrom(signPublicKey),
  verify: createVerifyOwnership(diffieHellman, trustedParties, trustThreshold)
})

export {
  CONTEXT_INITIATOR,
  CONTEXT_RESPONDER,
  calculateSafetyNumber,
  certify,
  createAlice,
  createBob,
  createCertificate,
  createCharlie,
  createDiffieHellman,
  createSign,
  createTrustedParties,
  generateKeyPair,
  generateKeyShare,
  generateSignKeyPair,
  identify,
  prove,
  trust,
  verifySignature,
  verify
}
