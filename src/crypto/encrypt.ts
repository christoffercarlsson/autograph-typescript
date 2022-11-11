import { alloc } from 'stedy/chunk'
import { CIPHER_AES256_GCM, encrypt as encryptMessage } from 'stedy/crypto'
import { AES_GCM_NONCE_SIZE } from '../constants'

const encrypt = (key: BufferSource, message: BufferSource) => {
  const nonce = alloc(AES_GCM_NONCE_SIZE)
  return encryptMessage(CIPHER_AES256_GCM, key, nonce, message)
}

export default encrypt
