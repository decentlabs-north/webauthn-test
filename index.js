/** This is a testbench with hacky but functional code */
import { decode } from 'cborg'
import { p256 } from '@noble/curves/p256'
import 'https://unpkg.com/ua-parser-js@1.0.35/src/ua-parser.js'
const RPID = window.location.hostname
// Ensure https unless localhost / fix surge annoyance on mobile
if (RPID !== 'localhost' && window.location.protocol === 'http:') {
  window.localhost = window.location.toString().replace('http:', 'https:')
}
// Main settings
const residentKey = 'preferred' // 'required': SK must be stored on authenticator
const userVerification = 'required' // Require PIN-code?

document.addEventListener('DOMContentLoaded', () => {
  const { browser, os, device, cpu } = new window.UAParser().getResult()
  setDiag({ ua: { browser, os, device, cpu } })
  document.getElementById('btn-create').addEventListener('click', create)
  document
    .getElementById('btn-sign')
    .addEventListener('click', () => sign(false))
  document
    .getElementById('btn-sign-disco')
    .addEventListener('click', () => sign(true))
  document.getElementById('btn-prf-create')
    .addEventListener('click', () => testPRF(true))
  document.getElementById('btn-prf-get')
    .addEventListener('click', () => testPRF(false))
  document.getElementById('diag-copy').addEventListener('click', () => {
    navigator.clipboard.writeText(document.getElementById('diagnostics').value)
  })
})

function setError (err) {
  setDiag({ error: err })
  document.getElementById('res-err').value = err.toString() + '\n' + err.stack
  window.scrollTo(0, document.body.getBoundingClientRect().height)
}

async function create () {
  console.log('CreateKey', RPID)
  try {
    const options = {
      publicKey: {
        challenge: random(32),
        rp: { id: RPID, name: 'Xorcery Inc.' },
        user: {
          id: random(32),
          name: document.getElementById('create-alias').value || 'testbench',
          displayName: 'testbench'
        },
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 } // ECDSA with SHA-256
        ],
        authenticatorSelection: {
          residentKey,
          userVerification
        }
      }
    }
    const cred = await navigator.credentials.create(options)
    setDiag({ create: { options } })
    window.createRes = cred
    console.log('create()', cred)
    setDiag({
      create: {
        credentialsId: cred.rawId,
        attestationObject: cred.response.attestationObject
      }
    })
    document.getElementById('res-create').value = toHex(cred.rawId)
    document.getElementById('res-create-att').value = toHex(cred.response.attestationObject)

    const authenticatorData = getAuthenticatorData(cred.response)
    setDiag({ create: { authenticatorData } })
    document.getElementById('res-create-auth').value = toHex(authenticatorData)
    if (authenticatorData.length) {
      const { publicKey } = decodeAuthenticatorData(authenticatorData) // TODO: hex not base64
      setDiag({ create: { publicKey } })
      document.getElementById('res-create-pk').value = toHex(publicKey)
    } else {
      setDiag({ create: { publicKey: '<Decode Failed>' } })
      document.getElementById('res-create-pk').value = '<Decode Failed>'
    }
  } catch (err) {
    console.error('create(FAILED)', err)
    setError(err)
  }
  // document.getElementById('res-pk').value = cred.response.
}

async function sign (discoverable = false) {
  try {
    const textPayload = document.getElementById('text-hash')
    if (!textPayload.value.length) {
      const dummy32 = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
      textPayload.value = dummy32
    }
    const hashOfCapability = fromHex(textPayload.value)
    const allowCredentials = []

    if (!discoverable) {
      const id = fromHex(document.getElementById('res-create').value)
      allowCredentials.push({ type: 'public-key', id })
    }
    const options = {
      publicKey: {
        rpId: RPID,
        challenge: hashOfCapability, // Uint8Array(32)
        allowCredentials,
        timeout: 240000,
        attestation: 'direct'
      }
    }
    setDiag({ sign: { options } })
    /** @type {PublicKeyCredential} */
    const res = await navigator.credentials.get(options)
    console.log(`sign(${discoverable})`, res)
    window.signRes = res
    // https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential
    // rawId prop seems to be part of spec: id = b64url(rawId)
    const credentialId = res.rawId
    const { clientDataJSON, signature } = res.response
    const authenticatorData = getAuthenticatorData(res.response)

    setDiag({ sign: { credentialId, clientDataJSON, signature, authenticatorData } })
    document.getElementById('res-sign-client').value = toHex(clientDataJSON)
    document.getElementById('res-sign-sig').value = toHex(signature)
    document.getElementById('res-sign-auth').value = toHex(authenticatorData)
    document.getElementById('res-sign-cid').value = toHex(credentialId)

    const recovered = recoverPublicKey(
      signature,
      authenticatorData,
      clientDataJSON,
      credentialId
    )
    const { pk0, pk1, ml0, ml1, publicKey } = recovered
    document.getElementById('res-sign-pk').value = bq`
      PK0 ${toHex(pk0)}
      PK1 ${toHex(pk1)}
      Overlaps: ${ml0} <=> ${ml1}

      Recovered Key:
          ${toHex(publicKey)}
    `
  } catch (err) {
    console.error('sign(FAILED)', err)
    setError(err)
  }
}

function setDiag (props) {
  window.diag ||= {}
  for (const key in props) {
    window.diag[key] ||= {}
    Object.assign(window.diag[key], props[key])
  }
  // Hex-encode all binary buffers
  const normalized = JSON.stringify(window.diag, (_, value) => {
    if (value instanceof ArrayBuffer) value = au8(value)
    if (value instanceof Uint8Array) return toHex(value)
    return value
  }, 2)
  // console.info('SetDiag', normalized)
  document.getElementById('diagnostics').value = normalized
}

// TODO: prob deprecate/move away
async function testPRF (create = true) {
  try {
    const clientData = {
      publicKey: {
        challenge: s2b(RPID), // not random
        extensions: {
          prf: {
            eval: {
              first: hash(RPID + '-sign'),
              second: hash(RPID + '-box') // Optional
            }
          }
        }
      }
    }
    let res
    if (create) {
      Object.assign(clientData.publicKey, {
        rp: { id: RPID, name: 'Xorcery Inc.' },
        user: {
          id: hash('prf-demo'),
          name: 'prf-demo',
          displayName: 'WebauthnPRF Test'
        },
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 } // ECDSA with SHA-256
        ],
        attestation: 'none', // ??? why?
        authenticatorSelection: {
          userVerification: 'required',
          residentKey: 'required',
          requireResidentKey: true // Obsolete, superseeded by 'residentKey'
        }
      })
      clientData.publicKey.extensions.credProps ||= true // ---
      clientData.publicKey.extensions.largeBlob ||= { support: 'preferred' } // ---
      console.log(clientData)
      res = await navigator.credentials.create(clientData)
    } else {
      clientData.publicKey.rpId = RPID
      clientData.publicKey.userVerification = 'required' // TODO: remove, this is the default?
      clientData.publicKey.allowCredentials = [] // Use discoverable
      res = await navigator.credentials.get(clientData)
    }
    window.prfRes = res
    const extRes = res.getClientExtensionResults()
    console.log(`TestPRF(${create}):`, clientData, res, extRes)

    document.getElementById('res-prf-value').value = JSON.stringify(extRes, null, 2)
    if (!extRes.prf?.results) throw new Error('PRF-extension not supported')
  } catch (err) {
    console.error('ext-prf(FAILED)', err)
    setError(err)
  }
}

// Hex/Bin converters
const b2hLUT = Array.from(new Array(256)).map((_, i) => i.toString(16).padStart(2, '0'))
const h2bLUT = Array.from(new Array(256)).map((_, i) => [i.toString(16).padStart(2, '0'), i]).reduce((m, n) => { m[n[0]] = n[1]; return m }, {})
function toHex (arr) {
  arr = au8(arr)
  let buf = ''
  for (let i = 0; i < arr.length; i++) buf += b2hLUT[arr[i]]
  return buf
}
/** @param {string} str */
function fromHex (str) {
  str = str.toLowerCase()
  const b = new Uint8Array(str.length >> 1)
  for (let i = 0; i < str.length >> 1; i++) b[i] = h2bLUT[str.slice(i * 2, i * 2 + 2)]
  return b
}

// Utf8/Bin converters
function s2b (str) { return new TextEncoder('utf8').encode(str) }
function b2s (buffer) { return new TextDecoder('utf8').decode(buffer) }

/* web-crypto async variant
async function hash (m) { // SHA256
  if (typeof m === 'string') m = s2b(m)
  return new Uint8Array(await crypto.subtle.digest('SHA-256', m))
} */

function random (n) {
  const b = new Uint8Array(n)
  crypto.getRandomValues(b)
  return b
}

function hash (m) { return p256.CURVE.hash(au8(m)) }

function recoverPublicKey (signature, authenticatorData, clientDataJSON, credentialId) {
  const msg = concat([authenticatorData, hash(clientDataJSON)])
  const msgHash = hash(msg)
  signature = au8(signature) // normalize to u8
  setDiag({ recover: { signature, authenticatorData, clientDataJSON, credentialId } })
  const pk0 = p256.Signature.fromDER(signature)
    .addRecoveryBit(0)
    .recoverPublicKey(msgHash)
    .toRawBytes(true)

  const pk1 = p256.Signature.fromDER(signature)
    .addRecoveryBit(1)
    .recoverPublicKey(msgHash)
    .toRawBytes(true)

  setDiag({ recover: { pk0, pk1 } })
  const ml0 = nOverlap(pk0.slice(1), credentialId)
  const ml1 = nOverlap(pk1.slice(1), credentialId)
  const publicKey = ml0 === ml1 ? new Uint8Array(2) : ml1 < ml0 ? pk0 : pk1
  setDiag({ recover: { ml0, ml1, publicKey } })
  return { pk0, pk1, ml0, ml1, publicKey }
}

/**
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {number}
 */
function nOverlap (a, b) {
  a = au8(a)
  b = au8(b)
  const m = Math.max(a.length, b.length)
  for (let i = 0; i < m; i++) if (a[i] !== b[i]) return i
}

/**
 * @param {Array<Uint8Array>} buffers
 * @returns Uint8Array
 */
function concat (buffers) {
  buffers = buffers.map(au8)
  const out = new Uint8Array(buffers.reduce((s, b) => s + b.length, 0))
  let o = 0
  for (const b of buffers) {
    out.set(b, o)
    o += b.length
  }
  return out
}

/**
 * Normalize authenticatorData across browsers
 */
function getAuthenticatorData (response) {
  if (response.getAuthenticatorData === 'function') return response.getAuthenticatorData() // only on Chrome
  if (response.authenticatorData) return response.authenticatorData // Sometimes not available on FF
  if (response.attestationObject) {
    const ao = decode(au8(response.attestationObject))
    return ao.authData
  }
  return null // getting authenticatorData failed
}

/**
 * multiline template literal that strips out leading/trailing whitespaces
 */
function bq (str, ...tokens) {
  str = [...str]
  for (let i = tokens.length; i > 0; i--) str.splice(i, 0, tokens.pop())
  return str.join('').split('\n').map(t => t.trim()).join('\n').trim()
}
const au8 = o => {
  if (o instanceof ArrayBuffer) return new Uint8Array(o)
  if (o instanceof Uint8Array) return o
  throw new Error('Uint8Array expected')
}

// -- Borrowed from js-did/packages/key-webauthn/src/index.ts
/**
 * Extracts PublicKey from AuthenticatorData as received from hardware key.
 *
 * See box `CREDENTIAL PUBLIC KEY` in picture:
 * https://w3c.github.io/webauthn/images/fido-attestation-structures.svg
 * @param {Uint8Array|ArrayBuffer} attestationObject As given by credentials.create().response.attestationObject
 */
function decodeAuthenticatorData (authData) {
  authData = au8(authData)
  // https://w3c.github.io/webauthn/#sctn-authenticator-data
  if (authData.length < 37) throw new Error('AuthenticatorDataTooShort')
  let o = 0
  const rpidHash = authData.slice(o, o += 32) // SHA-256 hash of rp.id

  const flags = authData[o++]
  // console.debug(`Flags: 0b` + flags.toString(2).padStart(8, '0'))
  if (!(flags & (1 << 6))) throw new Error('AuthenticatorData has no Key')

  const view = new DataView(authData.buffer)
  const signCounter = view.getUint32(o); o += 4

  // https://w3c.github.io/webauthn/#sctn-attested-credential-data
  const aaguid = authData.slice(o, o += 16)
  const clen = view.getUint16(o); o += 2
  const credentialId = authData.slice(o, o += clen)

  // https://datatracker.ietf.org/doc/html/rfc9052#section-7
  // const publicKey = decode(authData.slice(o)) // cborg.decode fails; Refuses to decode COSE use of numerical keys
  const cose = decodeCBORHack(authData.slice(o)) // Decode cbor manually

  // Section 'COSE Key Type Parameters'
  // https://www.iana.org/assignments/cose/cose.xhtml
  if (cose[1] !== 2) throw new Error('Expected EC Coordinate pair')
  if (cose[3] !== -7) throw new Error('Expected ES256 Algorithm')
  const x = cose[-2]
  const y = cose[-3]
  if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) throw new Error('Expected X and Y coordinate to be buffers')
  const publicKey = new Uint8Array(x.length + 1)
  publicKey[0] = 2 + (y[y.length - 1] & 1)
  publicKey.set(x, 1)
  return {
    rpidHash,
    flags,
    signCounter,
    aaguid,
    credentialId,
    publicKey,
    cose
  }
}

/**
 * Tiny unsafe CBOR decoder that supports COSE_key numerical keys
 * https://www.iana.org/assignments/cose/cose.xhtml
 * Section 'COSE Key Type Parameters'
 * @param {Uint8Array} buf
 */
function decodeCBORHack (buf) {
  if (!(buf instanceof Uint8Array)) throw new Error('Uint8ArrayExpected')
  const view = new DataView(buf.buffer)
  let o = 0
  const readByte = () => buf[o++]
  const readU8 = () => view.getUint8(o++) // @ts-ignore
  const readU16 = () => view.getUint16(o, undefined, o += 2) // @ts-ignore
  const readU32 = () => view.getUint16(o, undefined, o += 4) // @ts-ignore
  const readU64 = () => view.getBigUint64(o, undefined, o += 8) // @ts-ignore
  const readLength = l => l < 24 ? l : [readU8, readU16, readU32, readU64][l - 24]() // @ts-ignore
  const readMap = l => {
    const map = {} // @ts-ignore
    for (let i = 0; i < l; i++) map[readItem()] = readItem()
    return map
  } // @ts-ignore
  const readBuffer = l => buf.slice(o, o += l)
  function readItem () {
    const b = readByte()
    const l = readLength(b & 0x1f)
    switch (b >> 5) {
      case 0: return l // Uint
      case 1: return -(l + 1) // Negative integer
      case 2: return readBuffer(l) // binstr
      case 5: return readMap(l)
      default: throw new Error('UnsupportedType' + (b >> 5))
    }
  }
  return readItem()
}
