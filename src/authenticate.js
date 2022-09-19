import { alloc, append, concat, createFrom, writeUint16BE } from 'stedy/chunk'
import {
  CONTEXT_INITIATOR,
  PUBLIC_KEY_SIZE,
  SIGNATURE_SIZE
} from './constants.js'
import encrypt from './crypto/encrypt.js'
import deriveSecretKey from './utils/derive-secret-key.js'
import readKeyShare from './utils/read-key-share.js'

const createCertificate = (certificate) => {
  const entrySize = PUBLIC_KEY_SIZE + SIGNATURE_SIZE
  const entries = Math.min(certificate.byteLength / entrySize, 65535)
  return append(
    writeUint16BE(alloc(2), entries),
    certificate.subarray(0, entrySize * entries)
  )
}

const createMessage = async (sign, ourData, ourCertificate, theirKeyShare) => {
  const { ephemeralPublicKey } = readKeyShare(theirKeyShare)
  const signature = await sign(concat([ourData, ephemeralPublicKey]))
  return concat([signature, createCertificate(ourCertificate), ourData])
}

export const authenticate = async (
  sign,
  diffieHellman,
  context,
  ourData,
  ourCertificate,
  ourEphemeralPrivateKey,
  theirKeyShare
) => {
  const key = await deriveSecretKey(
    diffieHellman,
    context,
    ourEphemeralPrivateKey,
    theirKeyShare,
    context === CONTEXT_INITIATOR
  )
  const message = await createMessage(
    sign,
    ourData,
    ourCertificate,
    theirKeyShare
  )
  return encrypt(key, message)
}

export const prove = (
  sign,
  diffieHellman,
  ourData,
  ourCertificate,
  ourEphemeralPrivateKey,
  theirKeyShare
) =>
  authenticate(
    sign,
    diffieHellman,
    CONTEXT_INITIATOR,
    ourData,
    ourCertificate,
    ourEphemeralPrivateKey,
    theirKeyShare
  )

export const identify = (
  sign,
  diffieHellman,
  ourCertificate,
  ourEphemeralPrivateKey,
  theirKeyShare,
  context = CONTEXT_INITIATOR
) =>
  authenticate(
    sign,
    diffieHellman,
    context,
    createFrom(),
    ourCertificate,
    ourEphemeralPrivateKey,
    theirKeyShare
  )
