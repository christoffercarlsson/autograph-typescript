import { concat, createFrom, ENCODING_BASE64_URLSAFE } from 'stedy/bytes'

type TrustedPartyEntry = string | BufferSource

const createTrustedParties = (
  entries: TrustedPartyEntry[],
  encoding = ENCODING_BASE64_URLSAFE
) =>
  (entries || []).reduce(
    (trustedParties, identityKey) =>
      concat([createFrom(trustedParties), createFrom(identityKey, encoding)]),
    createFrom()
  ) as Uint8Array

export default createTrustedParties
