import { split } from 'stedy/chunk'
import { PUBLIC_KEY_SIZE } from '../constants.js'

const readKeyShare = (keyShare) => {
  const [signPublicKey, publicKey, ephemeralPublicKey] = split(
    keyShare,
    PUBLIC_KEY_SIZE
  )
  return { signPublicKey, publicKey, ephemeralPublicKey }
}

export default readKeyShare
