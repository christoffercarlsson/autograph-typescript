import { alloc } from 'stedy/bytes'
import { decrypt as decryptMessage } from 'stedy'
import { AES_GCM_NONCE_SIZE } from '../constants'

const decrypt = (key: BufferSource, ciphertext: BufferSource) => {
  const nonce = alloc(AES_GCM_NONCE_SIZE)
  return decryptMessage(key, nonce, ciphertext)
}

export default decrypt
