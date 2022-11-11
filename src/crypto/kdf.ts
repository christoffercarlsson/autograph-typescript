import { alloc, createFrom } from 'stedy/chunk'
import { HASH_SHA512, hkdf } from 'stedy/crypto'
import { HKDF_OUTPUT_SIZE, HKDF_SALT_SIZE } from '../constants'

const kdf = (sharedSecret: BufferSource, context: number) => {
  const salt = alloc(HKDF_SALT_SIZE)
  return hkdf(
    HASH_SHA512,
    sharedSecret,
    salt,
    createFrom([context]),
    HKDF_OUTPUT_SIZE
  )
}

export default kdf
