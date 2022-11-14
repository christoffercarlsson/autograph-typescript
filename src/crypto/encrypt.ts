import { alloc } from 'stedy/bytes'
import { encrypt as encryptMessage } from 'stedy'
import { AES_GCM_NONCE_SIZE } from '../constants'

const encrypt = (key: BufferSource, message: BufferSource) => {
  const nonce = alloc(AES_GCM_NONCE_SIZE)
  return encryptMessage(key, nonce, message)
}

export default encrypt
