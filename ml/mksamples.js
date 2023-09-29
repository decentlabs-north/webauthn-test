import { p256 } from '@noble/curves/p256'
const MASK32 = (1n << 32n) - 1n
const n_K = 10000
const n_S = 500
console.error(`Generating ${n_K} x ${n_S} samples`)

for (let i = 0; i < n_K; i++) {
    if (!(i % 8)) console.error('KEY', i, ((i / n_K) * 100).toFixed(2), '%')
    generateKeySamples(n_S)
}

function generateKeySamples (samples = 2000) {
    const secret = p256.utils.randomPrivateKey()
    const pk = p256.getPublicKey(secret)
    const ppk = p256.ProjectivePoint.fromHex(pk)
    const [pkx, pky] = [int256To8Float(ppk.px), int256To8Float(ppk.py)]

    for (let i = 0; i < samples; i++) {
        const msgHash = p256.CURVE.randomBytes(32)
        const sig = p256.sign(msgHash, secret).toDERRawBytes() // as recevied by webauthn
        const [pk0, pk1] = [0, 1].map(rBit =>
            p256.Signature.fromDER(sig)
            .addRecoveryBit(rBit)
            .recoverPublicKey(msgHash)
            .toRawBytes(true)
        )
        const rbit = cmp(pk0, pk)
            ? [1, 0] // bit = 0
            : [0, 1] // bit = 1

        const [ppk0, ppk1] = [pk0, pk1].map(k => p256.ProjectivePoint.fromHex(k))
        const [pk0x, pk0y, pk1x, pk1y] = [
            int256To8Float(ppk0.px),
            int256To8Float(ppk0.py),
            int256To8Float(ppk1.px),
            int256To8Float(ppk1.py)
        ]
        // Create a linear array of all inputs
        const sample = [
            ...pkx, // 8
            ...pky, // 16
            ...pk0x, // 24
            ...pk0y, // 32
            ...pk1x, // 40
            ...pk1y, // 48
            ...rbit // 50
        ]
        console.log(sample.join(','))
    }
}
function cmp(u8a, u8b) {
    if (u8a.length !== u8b.length) return false
    for (let i = 0; i < u8a.length; i++) if (u8a[i] !== u8b[i]) return false
    return true
}

function int256To8Float (i) {
    const floats = []
    for (let n = 0; n < 8; n++) {
        const seg = (i >> (BigInt(n) * 32n)) & MASK32
        floats.push(Number(seg) / 2 ** 32)
    }
    return floats
}
