import { Chunk } from 'stedy/bytes'
import diffieHellman from './crypto/diffie-hellman'
import partial from './utils/partial'

export type DiffieHellmanFunction = (
  theirPublicKey: BufferSource
) => Promise<Chunk>

const createDiffieHellman = (ourPrivateKey: BufferSource) =>
  partial(diffieHellman, ourPrivateKey) as DiffieHellmanFunction

export default createDiffieHellman
