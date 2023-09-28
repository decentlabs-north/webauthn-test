import { p256 } from '@noble/curves/p256'
import { hash as blake3 } from 'blake3'
const DBG = true
const ALGORITHMS = ['2bitXYParity', '1bitXParity', '8bitBlake3', '8bitXORChunk']
// Statistics
const S = {
  falsePositives: mkArray(ALGORITHMS.length, 0),
  recoveryRate: mkArray(ALGORITHMS.length, 1),
  iterations: 0,
  spread: mkArray(ALGORITHMS.length).map(() => mkArray(256, 0))
}

for (let n = 0; n < 32; n++) {
  // Generate Identity
  const secret = p256.utils.randomPrivateKey()
  const pk = p256.getPublicKey(secret)
  const ppk = p256.ProjectivePoint.fromHex(pk)
  const hints = ALGORITHMS.map((_, alg) => {
    const hint = genHint(ppk, alg)
    S.spread[alg][hint]++
    return hint
  })
  for (let m = 0; m < 0xff; m++) {
    const msgHash = p256.CURVE.randomBytes(32)
    const sig = p256.sign(msgHash, secret).toDERRawBytes() // as recevied by webauthn
    const [ppk0, ppk1] = [0, 1].map(rBit =>
      p256.Signature.fromDER(sig)
        .addRecoveryBit(rBit)
        .recoverPublicKey(msgHash)
    )
    const [pk0, pk1] = [ppk0, ppk1].map(point => point.toRawBytes(true))
    if (DBG) {
      console.log(`\n### ITERATION ${S.iterations} ###`)
      console.log('Expected', hints, toHex(pk))
      console.log('PK0', eql(pk, pk0), toHex(pk0))
      console.log('PK1', eql(pk, pk1), toHex(pk1))
      console.log('Rec | Alg | H0 | H1 | fP |')
    }

    // Generate hints and compare
    for (let alg = 0; alg < ALGORITHMS.length; alg++) {
      const [c0, c1] = [genHint(ppk0, alg), genHint(ppk1, alg)]
      if (c0 === c1) S.falsePositives[alg]++
      S.spread[alg][eql(pk, pk0) ? c1 : c0]++
      S.recoveryRate[alg] = 1 - (S.falsePositives[alg] / S.iterations) // Update success rateS
      if (DBG) {
        console.log(`${(S.recoveryRate[alg] * 100).toFixed(2)}% | ${ALGORITHMS[alg]} | ${c0} | ${c1} | ${S.falsePositives[alg]}`)
      }
    }

    S.iterations++
  }
}
console.log(`\n\nFINAL RESULTS\n== ${S.iterations} falsePositives: ${S.falsePositives} ~ ${((S.falsePositives / S.iterations) * 100).toFixed(4)}%`)
console.log(S)

function genHint (point, alg = 3) {
  const key = point.toRawBytes(true)
  switch (alg) {
    case 1: // 1bit X-parity check (~50%)
      return key[key.length - 1] & 1

    case 0: // 2bit: Y + X parity (~25% Collisions)
      return ((key[0] & 1) << 1) | (key[key.length - 1] & 1)

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
function mkArray (size, initialValue) { return Array.from(new Array(size)).map(_ => initialValue) }

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
