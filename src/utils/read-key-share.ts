import { createFrom, split } from 'stedy/chunk'
import { PUBLIC_KEY_SIZE } from '../constants'

const readKeyShare = (keyShare: BufferSource) => {
  const [signPublicKey, publicKey, ephemeralPublicKey] = split(
    createFrom(keyShare),
    PUBLIC_KEY_SIZE
  )
  return { signPublicKey, publicKey, ephemeralPublicKey }
}

export default readKeyShare
