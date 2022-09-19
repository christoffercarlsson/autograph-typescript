import { describe, it, expect } from 'stedy/test'
import { concat, createFrom } from 'stedy/chunk'
import {
  CONTEXT_INITIATOR,
  CONTEXT_RESPONDER,
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
  verify,
  calculateSafetyNumber
} from '../src/index.js'

const generateIdentity = async () => {
  const { publicKey: signPublicKey, privateKey: signPrivateKey } =
    await generateSignKeyPair()
  const { publicKey, privateKey } = await generateKeyPair()
  const diffieHellman = createDiffieHellman(privateKey)
  const sign = createSignFunction(signPrivateKey)
  return {
    diffieHellman,
    publicKey,
    privateKey,
    sign,
    signPublicKey,
    signPrivateKey
  }
}

export default describe('Protocol implementation', async () => {
  const alice = await generateIdentity()
  const bob = await generateIdentity()
  const charlie = await generateIdentity()
  const data = createFrom('Hello World')
  const certificate = createCertificate([
    [
      charlie.signPublicKey,
      await charlie.sign(concat([data, alice.signPublicKey]))
    ]
  ])
  return [
    it('should allow Bob and Charlie to establish trust', async () => {
      const { keyShare: bobKeyShare, privateKey: bobEphemeralPrivateKey } =
        await generateKeyShare(bob.signPublicKey, bob.publicKey)
      const {
        keyShare: charlieKeyShare,
        privateKey: charlieEphemeralPrivateKey
      } = await generateKeyShare(charlie.signPublicKey, charlie.publicKey)
      const bobCiphertext = await identify(
        bob.sign,
        bob.diffieHellman,
        createFrom(),
        bobEphemeralPrivateKey,
        charlieKeyShare,
        CONTEXT_INITIATOR
      )
      const bobVerification = await verify(
        charlie.diffieHellman,
        createTrustedParties(),
        0,
        charlieKeyShare,
        charlieEphemeralPrivateKey,
        bobKeyShare,
        bobCiphertext
      )
      expect(bobVerification.verified).toBe(true)
      expect(bobVerification.identityKey).toEqual(bob.signPublicKey)
      const charlieCiphertext = await identify(
        charlie.sign,
        charlie.diffieHellman,
        createFrom(),
        charlieEphemeralPrivateKey,
        bobKeyShare,
        CONTEXT_RESPONDER
      )
      const charlieVerification = await trust(
        bob.diffieHellman,
        createTrustedParties(),
        0,
        bobKeyShare,
        bobEphemeralPrivateKey,
        charlieKeyShare,
        charlieCiphertext
      )
      expect(charlieVerification.verified).toBe(true)
      expect(charlieVerification.identityKey).toEqual(charlie.signPublicKey)
      const bobSafetyNumber = await calculateSafetyNumber(
        bob.signPublicKey,
        bob.publicKey,
        charlieKeyShare
      )
      const charlieSafetyNumber = await calculateSafetyNumber(
        charlie.signPublicKey,
        charlie.publicKey,
        bobKeyShare
      )
      expect(bobSafetyNumber.byteLength).toBe(60)
      expect(bobSafetyNumber).toEqual(charlieSafetyNumber)
    }),

    it("should allow Charlie to certify Alice's ownership of her identity key and data", async () => {
      const { keyShare: aliceKeyShare, privateKey: aliceEphemeralPrivateKey } =
        await generateKeyShare(alice.signPublicKey, alice.publicKey)
      const {
        keyShare: charlieKeyShare,
        privateKey: charlieEphemeralPrivateKey
      } = await generateKeyShare(charlie.signPublicKey, charlie.publicKey)
      const ciphertext = await prove(
        alice.sign,
        alice.diffieHellman,
        data,
        createCertificate(),
        aliceEphemeralPrivateKey,
        charlieKeyShare
      )
      const certification = await certify(
        charlie.sign,
        charlie.diffieHellman,
        createTrustedParties(),
        0,
        createCertificate(),
        charlieKeyShare,
        charlieEphemeralPrivateKey,
        aliceKeyShare,
        ciphertext
      )
      const verification = await verifySignature(
        alice.diffieHellman,
        createTrustedParties(),
        0,
        data,
        aliceKeyShare,
        aliceEphemeralPrivateKey,
        charlieKeyShare,
        certification.authentication
      )
      expect(certification.verified).toBe(true)
      expect(certification.identityKey).toEqual(alice.signPublicKey)
      expect(certification.data).toEqual(data)
      expect(verification.verified).toBe(true)
      expect(verification.identityKey).toEqual(charlie.signPublicKey)
      expect(verification.signature.byteLength).toBe(64)
    }),

    it("should allow Bob to verify Alice's ownership of her identity key and data based on Charlie's public key and signature", async () => {
      const { keyShare: aliceKeyShare, privateKey: aliceEphemeralPrivateKey } =
        await generateKeyShare(alice.signPublicKey, alice.publicKey)
      const { keyShare: bobKeyShare, privateKey: bobEphemeralPrivateKey } =
        await generateKeyShare(bob.signPublicKey, bob.publicKey)
      const ciphertext = await prove(
        alice.sign,
        alice.diffieHellman,
        data,
        certificate,
        aliceEphemeralPrivateKey,
        bobKeyShare
      )
      const verification = await verify(
        bob.diffieHellman,
        charlie.signPublicKey,
        1,
        bobKeyShare,
        bobEphemeralPrivateKey,
        aliceKeyShare,
        ciphertext
      )
      expect(verification.verified).toBe(true)
      expect(verification.identityKey).toEqual(alice.signPublicKey)
      expect(verification.data).toEqual(data)
    })
  ]
})
