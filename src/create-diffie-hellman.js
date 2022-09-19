import { partial } from 'stedy/util'
import diffieHellman from './crypto/diffie-hellman.js'

const createDiffieHellman = (ourPrivateKey) =>
  partial(diffieHellman, ourPrivateKey)

export default createDiffieHellman
