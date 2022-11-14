import { concat, createFrom, split } from 'stedy/bytes'
import { SAFETY_NUMBER_DIVISOR, SAFETY_NUMBER_ITERATIONS } from './constants'
import hash from './crypto/hash'
import partial from './utils/partial'
import readKeyShare from './utils/read-key-share'

export type CalculateSafetyNumberFunction = (
  theirKeyShare: BufferSource
) => Promise<Uint8Array>

const encodeChunk = (chunk: Uint8Array) => {
  const [a, b, c, d, e] = chunk
  const number =
    (a * 2 ** 32 + b * 2 ** 24 + c * 2 ** 16 + d * 2 ** 8 + e) %
    SAFETY_NUMBER_DIVISOR
  const result = number.toString()
  return `${'0'.repeat(5 - result.length)}${result}`
}

const calculate = async (
  signPublicKey: BufferSource,
  publicKey: BufferSource
) => {
  const digest = await hash(
    concat([createFrom(signPublicKey), createFrom(publicKey)]),
    SAFETY_NUMBER_ITERATIONS
  )
  return split(digest.subarray(0, 30), 5)
    .map((chunk) => encodeChunk(chunk))
    .join('')
}

export const calculateSafetyNumber = async (
  ourSignPublicKey: BufferSource,
  ourPublicKey: BufferSource,
  theirKeyShare: BufferSource
) => {
  const { signPublicKey: theirSignPublicKey, publicKey: theirPublicKey } =
    readKeyShare(theirKeyShare)
  const fingerprints = await Promise.all([
    calculate(ourSignPublicKey, ourPublicKey),
    calculate(theirSignPublicKey, theirPublicKey)
  ])
  return createFrom(fingerprints.sort().join(''))
}

export const createCalculateSafetyNumber = (
  ourSignPublicKey: BufferSource,
  ourPublicKey: BufferSource
) =>
  partial(
    calculateSafetyNumber,
    ourSignPublicKey,
    ourPublicKey
  ) as CalculateSafetyNumberFunction
