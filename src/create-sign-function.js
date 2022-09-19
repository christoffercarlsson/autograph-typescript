import { partial } from 'stedy/util'
import sign from './crypto/sign.js'

const createSignFunction = (ourPrivateKey) => partial(sign, ourPrivateKey)

export default createSignFunction
