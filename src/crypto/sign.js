import { sign as signMessage } from 'stedy/crypto'
import { importPrivateSignKey } from '../utils/import-key.js'

const sign = async (ourPrivateKey, message) =>
  signMessage(message, await importPrivateSignKey(ourPrivateKey))

export default sign
