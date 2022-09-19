import { concat, createFrom, split } from 'stedy/chunk'
import { SAFETY_NUMBER_DIVISOR, SAFETY_NUMBER_ITERATIONS } from './constants.js'
import hash from './crypto/hash.js'
import readKeyShare from './utils/read-key-share.js'

const encodeChunk = (chunk) => {
  const [a, b, c, d, e] = chunk
  const number =
    (a * 2 ** 32 + b * 2 ** 24 + c * 2 ** 16 + d * 2 ** 8 + e) %
    SAFETY_NUMBER_DIVISOR
  const result = number.toString()
  return `${'0'.repeat(5 - result.length)}${result}`
}

const calculate = async (signPublicKey, publicKey) => {
  const digest = await hash(
    concat([signPublicKey, publicKey]),
    SAFETY_NUMBER_ITERATIONS
  )
  return split(digest.subarray(0, 30), 5)
    .map((chunk) => encodeChunk(chunk))
    .join('')
}

const calculateSafetyNumber = async (
  ourSignPublicKey,
  ourPublicKey,
  theirKeyShare
) => {
  const { signPublicKey: theirSignPublicKey, publicKey: theirPublicKey } =
    readKeyShare(theirKeyShare)
  const fingerprints = await Promise.all([
    calculate(ourSignPublicKey, ourPublicKey),
    calculate(theirSignPublicKey, theirPublicKey)
  ])
  return createFrom(fingerprints.sort().join(''))
}

export default calculateSafetyNumber
