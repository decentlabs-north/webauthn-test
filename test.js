import { p256 } from '@noble/curves/p256'
import { hash as blake3 } from 'blake3'
const DBG = true

const S = {
  falsePositives: 0,
  iterations: 0,
  spread: Array.from(new Array(256)).map(_ => 0)
}

for (let n = 0; n < 0xf; n++) {
  // Generate Identity
  const secret = p256.utils.randomPrivateKey()
  const pk = p256.getPublicKey(secret)
  const ppk = p256.ProjectivePoint.fromHex(pk)
  const hint = genHint(ppk)
  S.spread[hint]++
  for (let m = 0; m < 0xff; m++) {
    const msgHash = p256.CURVE.randomBytes(32)
    const sig = p256.sign(msgHash, secret).toDERRawBytes() // as recevied by webauthn
    const ppk0 = p256.Signature.fromDER(sig)
      .addRecoveryBit(0)
      .recoverPublicKey(msgHash)
    const pk0 = ppk0.toRawBytes(true)
    const ppk1 = p256.Signature.fromDER(sig)
      .addRecoveryBit(1)
      .recoverPublicKey(msgHash)
    const pk1 = ppk1.toRawBytes(true)

    const [c0, c1] = [genHint(ppk0), genHint(ppk1)]
    S.spread[eql(pk, pk0) ? c1 : c0]++
    if (c0 === c1) S.falsePositives++
    if (DBG) {
      console.log(`\n== ${S.iterations} falsePositives: ${S.falsePositives} ~ ${((S.falsePositives / S.iterations) * 100).toFixed(4)}%`)
      console.log('Expected', hint, toHex(pk))
      console.log('PK0', eql(pk, pk0), c0, toHex(pk0))
      console.log('PK1', eql(pk, pk1), c1, toHex(pk1))
      debugger
    }
    S.iterations++
  }
}
console.log(`\n\nFINAL RESULTS\n== ${S.iterations} falsePositives: ${S.falsePositives} ~ ${((S.falsePositives / S.iterations) * 100).toFixed(4)}%`)
console.log(S)

function genHint (point) {
  const key = point.toRawBytes(true)
  switch (3) {
    case 0: // 2bit: Y + X parity (~25% Collisions)
      return ((key[0] & 1) << 1) | (key[key.length - 1] & 1)

    case 1: // 1bit X-parity check (~50%)
      return key[key.length - 1] & 1

    case 2: // 8bit Blake3 (~0.36%)
      return blake3(key, { length: 1 })[0]

    case 3: // 8bit XOR-chunk (~0.33%)
      return key.slice(1).reduce((s, b) => s ^ b, key[0] & 1 ? 0b10101010 : 0b01010101)
  }
}

function toHex (u8) { return Buffer.from(u8).hexSlice() }
function eql (a, b) {
  for (let i = 0; i < Math.max(a.length, b.length); i++) if (a[i] !== b[i]) return false
  return true
}
export function mod (a, b) {
  const result = a % b
  return result >= BigInt(0) ? result : b + result
}

/*
const msg1 = p256.CURVE.hash('Hello')
const msg2 = p256.CURVE.hash('World')

const sig1 = p256.sign(msg1, secret).toDERRawBytes()
const sig2 = p256.sign(msg2, secret).toDERRawBytes()

const m1pk0 = p256.Signature.fromDER(sig1)
  .addRecoveryBit(0)
  .recoverPublicKey(msg1)
  .toRawBytes(true)
const m1pk1 = p256.Signature.fromDER(sig1)
  .addRecoveryBit(1)
  .recoverPublicKey(msg1)
  .toRawBytes(true)

const m2pk0 = p256.Signature.fromDER(sig2)
  .addRecoveryBit(0)
  .recoverPublicKey(msg2)
  .toRawBytes(true)
const m2pk1 = p256.Signature.fromDER(sig2)
  .addRecoveryBit(1)
  .recoverPublicKey(msg2)
  .toRawBytes(true)

console.log(`
PK: ${toHex(pk)}
Expected Parity: ${pk[0] == 2 ? 0 : 1}

Recovery from Message1
PK0: ${toHex(m1pk0)}
PK1: ${toHex(m1pk1)}

Recovery from Message2
PK0: ${toHex(m2pk0)}
PK1: ${toHex(m2pk1)}
`)
*/
