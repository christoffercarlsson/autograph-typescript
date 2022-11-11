import { HASH_SHA512, hash as digest } from 'stedy/crypto'

const hash = (message: BufferSource, iterations: number) =>
  digest(HASH_SHA512, message, iterations)

export default hash
