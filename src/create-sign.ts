import sign from './crypto/sign'
import partial from './utils/partial'

export type SignFunction = (message: BufferSource) => Promise<Uint8Array>

const createSign = (ourPrivateKey: BufferSource) =>
  partial(sign, ourPrivateKey) as SignFunction

export default createSign
