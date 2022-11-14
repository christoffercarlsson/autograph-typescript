import { alloc, createFrom } from 'stedy/bytes'
import { hkdf } from 'stedy'
import { HKDF_OUTPUT_SIZE, HKDF_SALT_SIZE } from '../constants'

const kdf = (sharedSecret: BufferSource, context: number) => {
  const salt = alloc(HKDF_SALT_SIZE)
  return hkdf(sharedSecret, salt, createFrom([context]), HKDF_OUTPUT_SIZE)
}

export default kdf
