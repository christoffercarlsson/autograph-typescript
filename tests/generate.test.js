import { describe, expect, it } from 'stedy/test'
import { concat, startsWith } from 'stedy/chunk'
import {
  generateKeyPair,
  generateKeyShare,
  generateSignKeyPair
} from '../src/index.js'

export default describe('Identity key pair and key share message generation', () => [
  it('should generate an Ed25519 identity key pair', async () => {
    const { publicKey, privateKey } = await generateSignKeyPair()
    expect(publicKey.byteLength).toBe(32)
    expect(privateKey.byteLength).toBe(32)
  }),

  it('should generate a X25519 identity key pair', async () => {
    const { publicKey, privateKey } = await generateKeyPair()
    expect(publicKey.byteLength).toBe(32)
    expect(privateKey.byteLength).toBe(32)
  }),

  it('should generate a key share', async () => {
    const { publicKey: ourSignPublicKey } = await generateSignKeyPair()
    const { publicKey: ourPublicKey } = await generateKeyPair()
    const { keyShare, privateKey } = await generateKeyShare(
      ourSignPublicKey,
      ourPublicKey
    )
    expect(keyShare.byteLength).toBe(96)
    expect(privateKey.byteLength).toBe(32)
    expect(startsWith(keyShare, concat([ourSignPublicKey, ourPublicKey]))).toBe(
      true
    )
  })
])
