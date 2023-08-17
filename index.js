// import { decode } from 'cborg'
import { p256 } from '@noble/curves/p256'
const RPID = window.location.hostname
// Ensure https unless localhost / fix surge annoyance on mobile
if (RPID !== 'localhost' && window.location.protocol === 'http:') {
  window.localhost = window.location.toString().replace('http:', 'https:')
}

document.getElementById("btn-create").addEventListener("click", create)
document
  .getElementById("btn-sign")
  .addEventListener("click", () => sign(false))
document
  .getElementById("btn-sign-disco")
  .addEventListener("click", () => sign(true))
document.getElementById('btn-prf-create')
  .addEventListener('click', () => testPRF(true))
document.getElementById('btn-prf-get')
  .addEventListener('click', () => testPRF(false))

function setError (err) {
  document.getElementById("res-err").value = err.toString() + '\n' + err.stack
  scrollTo(0, document.body.getBoundingClientRect().height)
}

async function create () {
  console.log("CreateKey", RPID)
  try {
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge: random(32),
        rp: { id: RPID, name: "Xorcery Inc." },
        user: {
          id: random(32),
          name: "ceramicuser",
          displayName: "Ceramic User"
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 }, // ECDSA with SHA-256
        ],
        authenticatorSelection: {
          residentKey: "required",
          userVerification: "required",
          requireResidentKey: true,
        }
      }
    })

    window.createRes = cred
    console.log("create()", cred)
    document.getElementById("res-create").value = cred.id
    /* Skipping DER-encoded public-key
    document.getElementById("res-create-pk").value =
      typeof cred.response.getPublicKey === "function"
      ? toHex(cred.response.getPublicKey()) // TODO: Returns undef on android
      : "response.getPublicKey() not available"
    */

    document.getElementById("res-create-att").value = toHex(cred.response.attestationObject)
    const authData = typeof cred.response.getAuthenticatorData === 'function'
      ? cred.response.getAuthenticatorData()
      : cred.response.authenticatorData
    document.getElementById("res-create-auth").value = toHex(authData)
    document.getElementById("res-create-pk").value = toHex(decodeAuthenticatorData(authData).pk)
  } catch (err) {
    console.error("create(FAILED)", err)
    setError(err)
  }
  // document.getElementById('res-pk').value = cred.response.
}

async function sign(discoverable = false) {
  try {
    const textPayload = document.getElementById("text-hash")
    if (!textPayload.value.length) {
      const dummy32 = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
      textPayload.value =  dummy32
    }
    const hashOfCapability = fromHex(textPayload.value)
    const allowCredentials = []

    if (!discoverable) {
      const id = fromHex(document.getElementById("res-create").value)
      allowCredentials.push({ type: "public-key", id })
    }
    /** @type {PublicKeyCredential} */
    const res = await navigator.credentials.get({
      publicKey: {
        rpId: RPID,
        challenge: hashOfCapability, // Uint8Array(32)
        allowCredentials,
        timeout: 240000,
        attestation: 'direct'
      }
    })
    console.log(`sign(${discoverable})`, res)
    window.signRes = res
    // https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential
    // rawId prop seems to be part of spec: id = b64url(rawId)
    const credentialId = res.rawId
    const { clientDataJSON, signature } = res.response
    const authenticatorData = typeof res.response.getAuthenticatorData === 'function'
      ? res.response.getAuthenticatorData()
      : res.response.authenticatorData
    document.getElementById("res-sign-client").value = toHex(clientDataJSON)
    document.getElementById("res-sign-sig").value = toHex(signature)
    document.getElementById("res-sign-auth").value = toHex(authenticatorData)
    document.getElementById('res-sign-cid').value = toHex(credentialId)
    document.getElementById("res-sign-pk").value = recoverPublicKey(
      signature,
      authenticatorData,
      clientDataJSON,
      credentialId
    )
  } catch (err) {
    console.error("sign(FAILED)", err)
    setError(err)
  }
}

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
        rp: { id: RPID, name: "Xorcery Inc." },
        user: {
          id: hash('prf-demo'),
          name: 'prf-demo',
          displayName: 'WebauthnPRF Test'
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 }, // ECDSA with SHA-256
        ],
        attestation: 'none', // ??? why?
        authenticatorSelection: {
          residentKey: 'required',
          userVerification: 'required',
          requireResidentKey: true, // Obsolete, superseeded by 'residentKey'
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
    console.error("ext-prf(FAILED)", err)
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
function fromHex(str) {
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

function random(n) {
  const b = new Uint8Array(n)
  crypto.getRandomValues(b)
  return b
}

function hash (m) { return p256.CURVE.hash(au8(m)) }

function recoverPublicKey(signature, authenticatorData, clientDataJSON, credentialId) {
  // printa båda x1 och x2 (se skillnad på recovered nycklar)
  // korellatera mx2 och mx2 (recovera från msg1 och msg2 se om recovered är samma)
  // const recoveryBit = 0 // p256.ProjectivePoint.fromHex(publicKey).hasEvenY() ? 0 : 1
  const msg = concat([authenticatorData, hash(clientDataJSON)])
  const msgHash =  hash(msg)
  signature = au8(signature) // normalize to u8
  const pk0 = p256.Signature.fromDER(signature)
    .addRecoveryBit(0)
    .recoverPublicKey(msgHash)
    .toRawBytes(true)

  const pk1 = p256.Signature.fromDER(signature)
    .addRecoveryBit(1)
    .recoverPublicKey(msgHash)
    .toRawBytes(true)

  return bq`
    PK0 ${toHex(pk0)}
    PK1 ${toHex(pk1)}
  `
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
