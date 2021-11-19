const { randomBytes } = require('crypto')
const bip39 = require('bip39')
// similar feature sign and verify
const hdkey = require('hdkey')
const secp256k1 = require('secp256k1')

// generate 12 words BIP39
// const mnemonic = bip39.generateMnemonic()
// console.log(mnemonic)
// => rubber ... ... ... jump
const seed = bip39.mnemonicToSeedSync('rubber goose size jump special toy nothing isolate urban act control able')
// const seed = bip39.mnemonicToSeedSync(mnemonic)

const root = hdkey.fromMasterSeed(seed)
// deriving the first account based on BIP44
const path = "m/44'/0'/0'"
const num = "0"
const child = root.derive(path+`0/${num}`)
console.log("privatekeyhex:",child.privateKey.toString('hex'))
// => privatekeyhex: 42c7055fc26c8429d9a0cc173c6a36eb68e555393222e033f52b8fd839458505
console.log("publickeyhex:",child.publicKey.toString('hex'))
// => publickeyhex: 02f199a9c596f9151de88379994550de4f0447547c197589b9b3222ab90701cb2e

// generate privKey
const privKey = child.privateKey
// get the public key in a compressed format
const pubKey = secp256k1.publicKeyCreate(child.privateKey)
console.log("publickeyhex:", Buffer.from(pubKey).toString('hex'))
// => publickeyhex: 02f199a9c596f9151de88379994550de4f0447547c197589b9b3222ab90701cb2e

// randon msg
const msg = randomBytes(32)
// sign the message
// sign with hdkey lib
const sigChild = child.sign(msg)
// sign with secp256k1 lib
const sigObj = secp256k1.ecdsaSign(msg, privKey)
console.log("sigObj:", Buffer.from(sigObj.signature).toString('hex'))
console.log("sigChild:",sigChild.toString('hex'))
// verify the signature
// verify with hdkey lib
console.log(child.verify(msg,sigChild))
// verify with secp256k1 lib
console.log(secp256k1.ecdsaVerify(sigObj.signature, msg, pubKey))
// => true