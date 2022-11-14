import diffieHellman from './crypto/diffie-hellman'
import partial from './utils/partial'

export type DiffieHellmanFunction = (
  theirPublicKey: BufferSource
) => Promise<Uint8Array>

const createDiffieHellman = (ourPrivateKey: BufferSource) =>
  partial(diffieHellman, ourPrivateKey) as DiffieHellmanFunction

export default createDiffieHellman
