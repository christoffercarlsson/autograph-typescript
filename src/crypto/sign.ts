import { sign as signMessage } from 'stedy/crypto'
import { importPrivateSignKey } from '../utils/import-key'

const sign = async (ourPrivateKey: BufferSource, message: BufferSource) =>
  signMessage(message, await importPrivateSignKey(ourPrivateKey))

export default sign
