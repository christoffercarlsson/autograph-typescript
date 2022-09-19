import { deriveSharedSecret } from 'stedy/crypto'
import { DH_OUTPUT_SIZE } from '../constants.js'
import { importPrivateKey, importPublicKey } from '../utils/import-key.js'

const diffieHellman = async (ourPrivateKey, theirPublicKey) =>
  deriveSharedSecret(
    await importPrivateKey(ourPrivateKey),
    await importPublicKey(theirPublicKey),
    DH_OUTPUT_SIZE
  )

export default diffieHellman
