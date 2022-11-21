import { createFrom } from 'stedy/bytes'
import { PUBLIC_KEY_SIZE } from '../constants'

const readKeyShare = (keyShare: BufferSource) => {
  const [signPublicKey, publicKey, ephemeralPublicKey] =
    createFrom(keyShare).split(PUBLIC_KEY_SIZE)
  return { signPublicKey, publicKey, ephemeralPublicKey }
}

export default readKeyShare
