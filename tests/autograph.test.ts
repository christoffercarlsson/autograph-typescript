import { concat, createFrom } from 'stedy/chunk'
import {
  createDiffieHellman,
  createSign,
  generateKeyPair,
  generateSignKeyPair,
  createAlice,
  createBob,
  createCharlie,
  Bob,
  Alice,
  Charlie,
  DiffieHellmanFunction,
  SignFunction
} from '../src'

type BobExtended = Bob & {
  diffieHellman: DiffieHellmanFunction
  sign: SignFunction
}

type CharlieExtended = Charlie & {
  sign: SignFunction
}

type Identity = {
  diffieHellman: DiffieHellmanFunction
  publicKey: Uint8Array
  sign: SignFunction
  signPublicKey: Uint8Array
}

const generateIdentity = async (): Promise<Identity> => {
  const { publicKey: signPublicKey, privateKey: signPrivateKey } =
    await generateSignKeyPair()
  const { publicKey, privateKey } = await generateKeyPair()
  return {
    diffieHellman: createDiffieHellman(privateKey),
    publicKey,
    sign: createSign(signPrivateKey),
    signPublicKey
  }
}

const generateAlice = async (): Promise<Alice> => {
  const { diffieHellman, publicKey, sign, signPublicKey } =
    await generateIdentity()
  return createAlice(
    signPublicKey,
    publicKey,
    sign,
    diffieHellman,
    createFrom(),
    0
  )
}

const generateBob = async (): Promise<BobExtended> => {
  const { diffieHellman, publicKey, sign, signPublicKey } =
    await generateIdentity()
  const bob = createBob(
    signPublicKey,
    publicKey,
    sign,
    diffieHellman,
    createFrom(),
    0
  )
  return {
    ...bob,
    diffieHellman,
    sign
  }
}

const generateCharlie = async (): Promise<CharlieExtended> => {
  const { diffieHellman, publicKey, sign, signPublicKey } =
    await generateIdentity()
  const charlie = createCharlie(
    signPublicKey,
    publicKey,
    sign,
    diffieHellman,
    createFrom(),
    0
  )
  return {
    ...charlie,
    sign
  }
}

const generateCertificate = async (
  charlie: CharlieExtended,
  alice: Alice,
  data: Uint8Array
) => {
  const signature = await charlie.sign(concat([data, alice.signPublicKey]))
  return concat([charlie.signPublicKey, signature])
}

describe('Protocol implementation', () => {
  const data = createFrom('Hello World')
  let alice: Alice,
    bob: BobExtended,
    charlie: CharlieExtended,
    certificate: Uint8Array
  beforeEach(async () => {
    alice = await generateAlice()
    bob = await generateBob()
    charlie = await generateCharlie()
    certificate = await generateCertificate(charlie, alice, data)
  })

  it('should allow Bob and Charlie to establish trust', async () => {
    const { keyShare: bobKeyShare, privateKey: bobEphemeralPrivateKey } =
      await bob.generateKeyShare()
    const {
      keyShare: charlieKeyShare,
      privateKey: charlieEphemeralPrivateKey
    } = await charlie.generateKeyShare()
    const bobCiphertext = await bob.identify(
      bobEphemeralPrivateKey,
      charlieKeyShare
    )
    const bobVerification = await charlie.verify(
      charlieKeyShare,
      charlieEphemeralPrivateKey,
      bobKeyShare,
      bobCiphertext
    )
    expect(bobVerification.verified).toBe(true)
    expect(bobVerification.identityKey).toEqual(bob.signPublicKey)
    const charlieCiphertext = await charlie.identify(
      charlieEphemeralPrivateKey,
      bobKeyShare
    )
    const charlieVerification = await bob.trust(
      bobKeyShare,
      bobEphemeralPrivateKey,
      charlieKeyShare,
      charlieCiphertext
    )
    expect(charlieVerification.verified).toBe(true)
    expect(charlieVerification.identityKey).toEqual(charlie.signPublicKey)
    const bobSafetyNumber = await bob.calculateSafetyNumber(charlieKeyShare)
    const charlieSafetyNumber = await charlie.calculateSafetyNumber(bobKeyShare)
    expect(bobSafetyNumber.byteLength).toBe(60)
    expect(bobSafetyNumber).toEqual(charlieSafetyNumber)
  })

  it("should allow Charlie to certify Alice's ownership of her identity key and data", async () => {
    const { keyShare: aliceKeyShare, privateKey: aliceEphemeralPrivateKey } =
      await alice.generateKeyShare()
    const {
      keyShare: charlieKeyShare,
      privateKey: charlieEphemeralPrivateKey
    } = await charlie.generateKeyShare()
    const ciphertext = await alice.prove(
      data,
      createFrom(),
      aliceEphemeralPrivateKey,
      charlieKeyShare
    )
    const certification = await charlie.certify(
      charlieKeyShare,
      charlieEphemeralPrivateKey,
      aliceKeyShare,
      ciphertext
    )
    const verification = await alice.verifySignature(
      data,
      aliceKeyShare,
      aliceEphemeralPrivateKey,
      charlieKeyShare,
      certification.authentication
    )
    expect(certification.verified).toBe(true)
    expect(certification.identityKey).toEqual(alice.signPublicKey)
    expect(verification.verified).toBe(true)
    expect(verification.identityKey).toEqual(charlie.signPublicKey)
    expect(verification.data.byteLength).toBe(64)
  })

  it("should allow Bob to verify Alice's ownership of her identity key and data based on Charlie's public key and signature", async () => {
    const bobWithCharlie = createBob(
      bob.signPublicKey,
      bob.publicKey,
      bob.sign,
      bob.diffieHellman,
      charlie.signPublicKey,
      1
    )
    const { keyShare: aliceKeyShare, privateKey: aliceEphemeralPrivateKey } =
      await alice.generateKeyShare()
    const { keyShare: bobKeyShare, privateKey: bobEphemeralPrivateKey } =
      await bobWithCharlie.generateKeyShare()
    const ciphertext = await alice.prove(
      data,
      certificate,
      aliceEphemeralPrivateKey,
      bobKeyShare
    )
    const verification = await bobWithCharlie.verify(
      bobKeyShare,
      bobEphemeralPrivateKey,
      aliceKeyShare,
      ciphertext
    )
    expect(verification.verified).toBe(true)
    expect(verification.identityKey).toEqual(alice.signPublicKey)
    expect(verification.data).toEqual(data)
  })
})
