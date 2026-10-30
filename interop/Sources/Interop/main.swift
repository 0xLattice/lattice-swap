import Foundation
import LatticePrimitives
import LatticeValidation
import Multikey
import cashew

// A Nexus spend out of the lock address: debit address(A), credit a fixed
// recipient, leave a miner surplus. Deterministic, so `payload` and `verify`
// rebuild the same body.
func multikeyHex(_ rawHex: String) -> String {
    Multikey(keyType: .ed25519, keyBytes: Data(hex: rawHex)!).hexEncoded
}

func spend(from jointRawHex: String, nonce: UInt64 = 0) -> HeaderImpl<TransactionBody> {
    let owner = CryptoUtils.createAddress(from: multikeyHex(jointRawHex))
    let fixedRecipient = CryptoUtils.createAddress(from: multikeyHex(String(repeating: "11", count: 32)))
    let body = TransactionBody(
        accountActions: [
            AccountAction(owner: owner, delta: -1_000),
            AccountAction(owner: fixedRecipient, delta: 990),
        ],
        actions: [], depositActions: [], receiptActions: [], withdrawalActions: [],
        signers: [owner], nonce: nonce, chainPath: ["Nexus"])
    return try! HeaderImpl(node: body)
}

let args = CommandLine.arguments
switch args[1] {
case "payload":   // payload <A>: the exact bytes Ed25519 signs
    let header = spend(from: args[2], nonce: UInt64(args.count > 3 ? args[3] : "0")!)
    let preimage = TransactionSigning.preimage(bodyHeader: header)!
    FileHandle.standardOutput.write(Data((CryptoUtils.signatureDomain + preimage).utf8))
case "verify":    // verify <A> <sig> <signingPubRaw>: the consensus signature rules
    let header = spend(from: args[2])
    let tx = Transaction(signatures: [multikeyHex(args[4]): args[3]], body: header)
    print("address(A)=\(header.node!.signers[0])")
    print("signaturesAreValid=\(tx.signaturesAreValid()) signaturesMatchSigners=\(tx.signaturesMatchSigners())")
default:
    fatalError("usage")
}
