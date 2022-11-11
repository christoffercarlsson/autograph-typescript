import { verify as verifyMessage } from 'stedy/crypto'
import { importPublicSignKey } from '../utils/import-key'

const verify = async (
  data: BufferSource,
  publicKey: BufferSource,
  signature: BufferSource
) => verifyMessage(data, await importPublicSignKey(publicKey), signature)

export default verify
