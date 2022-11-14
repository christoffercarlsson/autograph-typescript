import { concat, createFrom, ENCODING_BASE64_URLSAFE } from 'stedy/bytes'

export type CertificateEntry = {
  identityKey: string | BufferSource
  signature: string | BufferSource
}

const createCertificate = (
  entries: CertificateEntry[],
  encoding = ENCODING_BASE64_URLSAFE
) =>
  (entries || []).reduce(
    (certificate, { identityKey, signature }) =>
      concat([
        certificate,
        createFrom(identityKey, encoding),
        createFrom(signature, encoding)
      ]),
    createFrom()
  )

export default createCertificate
