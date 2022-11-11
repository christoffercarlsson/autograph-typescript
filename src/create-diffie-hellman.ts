import { partial } from 'stedy/util'
import diffieHellman from './crypto/diffie-hellman'

export type DiffieHellmanFunction = (
  theirPublicKey: BufferSource
) => Promise<BufferSource>

const createDiffieHellman = (ourPrivateKey: BufferSource) =>
  partial(diffieHellman, ourPrivateKey) as DiffieHellmanFunction

export default createDiffieHellman
