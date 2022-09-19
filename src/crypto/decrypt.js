import { alloc } from 'stedy/chunk'
import { CIPHER_AES256_GCM, decrypt as decryptMessage } from 'stedy/crypto'
import { AES_GCM_NONCE_SIZE } from '../constants.js'

const decrypt = (key, ciphertext) => {
  const nonce = alloc(AES_GCM_NONCE_SIZE)
  return decryptMessage(CIPHER_AES256_GCM, key, nonce, ciphertext)
}

export default decrypt
