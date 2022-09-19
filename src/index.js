import { identify, prove } from './authenticate.js'
import { CONTEXT_INITIATOR, CONTEXT_RESPONDER } from './constants.js'
import calculateSafetyNumber from './calculate-safety-number.js'
import certify from './certify.js'
import createCertificate from './create-certificate.js'
import createDiffieHellman from './create-diffie-hellman.js'
import createSignFunction from './create-sign-function.js'
import createTrustedParties from './create-trusted-parties.js'
import {
  generateKeyPair,
  generateKeyShare,
  generateSignKeyPair
} from './generate.js'
import trust from './trust.js'
import verifySignature from './verify-signature.js'
import { verifyOwnership as verify } from './verify.js'

export {
  CONTEXT_INITIATOR,
  CONTEXT_RESPONDER,
  calculateSafetyNumber,
  certify,
  createCertificate,
  createDiffieHellman,
  createSignFunction,
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
