import { alloc, append, concat, createFrom, writeUint16BE } from 'stedy/bytes'
import { CONTEXT_INITIATOR, PUBLIC_KEY_SIZE, SIGNATURE_SIZE } from './constants'
import type { DiffieHellmanFunction } from './create-diffie-hellman'
import type { SignFunction } from './create-sign'
import encrypt from './crypto/encrypt'
import deriveSecretKey from './utils/derive-secret-key'
import partial from './utils/partial'
import readKeyShare from './utils/read-key-share'

export type IdentifyFunction = (
  ourEphemeralPrivateKey: BufferSource,
  theirKeyShare: BufferSource
) => Promise<Uint8Array>

export type ProveFunction = (
  ourData: BufferSource,
  ourCertificate: BufferSource,
  ourEphemeralPrivateKey: BufferSource,
  theirKeyShare: BufferSource
) => Promise<Uint8Array>

const createCertificate = (certificate: Uint8Array) => {
  const entrySize = PUBLIC_KEY_SIZE + SIGNATURE_SIZE
  const entries = Math.min(certificate.byteLength / entrySize, 65535)
  return append(
    writeUint16BE(alloc(2), entries),
    certificate.subarray(0, entrySize * entries)
  )
}

const createMessage = async (
  sign: SignFunction,
  ourData: BufferSource,
  ourCertificate: BufferSource,
  theirKeyShare: BufferSource
) => {
  const data = createFrom(ourData)
  const { ephemeralPublicKey } = readKeyShare(theirKeyShare)
  const signature = await sign(concat([data, ephemeralPublicKey]))
  return concat([
    createFrom(signature),
    createCertificate(createFrom(ourCertificate)),
    data
  ])
}

export const authenticate = async (
  sign: SignFunction,
  diffieHellman: DiffieHellmanFunction,
  context: number,
  ourData: BufferSource,
  ourCertificate: BufferSource,
  ourEphemeralPrivateKey: BufferSource,
  theirKeyShare: BufferSource
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

export const identify = (
  sign: SignFunction,
  diffieHellman: DiffieHellmanFunction,
  context: number,
  ourCertificate: BufferSource,
  ourEphemeralPrivateKey: BufferSource,
  theirKeyShare: BufferSource
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

export const prove = (
  sign: SignFunction,
  diffieHellman: DiffieHellmanFunction,
  context: number,
  ourData: BufferSource,
  ourCertificate: BufferSource,
  ourEphemeralPrivateKey: BufferSource,
  theirKeyShare: BufferSource
) =>
  authenticate(
    sign,
    diffieHellman,
    context,
    ourData,
    ourCertificate,
    ourEphemeralPrivateKey,
    theirKeyShare
  )

export const createIdentify = (
  sign: SignFunction,
  diffieHellman: DiffieHellmanFunction,
  context: number,
  ourCertificate?: BufferSource
) =>
  partial(
    identify,
    sign,
    diffieHellman,
    context,
    ourCertificate || createFrom()
  ) as IdentifyFunction

export const createProve = (
  sign: SignFunction,
  diffieHellman: DiffieHellmanFunction,
  context: number
) => partial(prove, sign, diffieHellman, context) as ProveFunction
