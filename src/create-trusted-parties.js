import { concat, createFrom, ENCODING_BASE64_URLSAFE, split } from 'stedy/chunk'
import { PUBLIC_KEY_SIZE } from './constants.js'

const ensureArray = (value) => {
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
    return split(createFrom(value), PUBLIC_KEY_SIZE)
  }
  if (
    value !== undefined &&
    value !== null &&
    typeof value[Symbol.iterator] === 'function'
  ) {
    return [...(value instanceof Map ? value.values() : value)]
  }
  return []
}

const createTrustedParties = (entries, encoding = ENCODING_BASE64_URLSAFE) =>
  ensureArray(entries).reduce(
    (trustedParties, identityKey) =>
      concat([trustedParties, createFrom(identityKey, encoding)]),
    createFrom()
  )

export default createTrustedParties
