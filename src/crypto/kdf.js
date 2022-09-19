import { alloc } from 'stedy/chunk'
import { HASH_SHA512, hkdf } from 'stedy/crypto'
import { HKDF_OUTPUT_SIZE, HKDF_SALT_SIZE } from '../constants.js'

export const kdf = (sharedSecret, context) => {
  const salt = alloc(HKDF_SALT_SIZE)
  return hkdf(HASH_SHA512, sharedSecret, salt, context, HKDF_OUTPUT_SIZE)
}

export default kdf
