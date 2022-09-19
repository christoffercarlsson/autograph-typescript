import { verify as verifyMessage } from 'stedy/crypto'
import { importPublicSignKey } from '../utils/import-key.js'

const verify = async (data, publicKey, signature) =>
  verifyMessage(data, await importPublicSignKey(publicKey), signature)

export default verify
