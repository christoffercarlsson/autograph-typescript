import { partial } from 'stedy/util'
import sign from './crypto/sign'

export type SignFunction = (message: BufferSource) => Promise<Uint8Array>

const createSign = (ourPrivateKey: BufferSource) =>
  partial(sign, ourPrivateKey) as SignFunction

export default createSign
