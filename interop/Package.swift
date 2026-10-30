// swift-tools-version: 6.0
import PackageDescription

// Checks Rust-signed joint-key transactions with Lattice's own consensus
// signature rules. Pinned to the Lattice release the swap targets.
let package = Package(
    name: "Interop",
    platforms: [.macOS(.v15)],
    dependencies: [
        .package(url: "https://github.com/0xLattice/Lattice.git", exact: "54.2.1"),
        .package(url: "https://github.com/0xLattice/Multikey.git", exact: "1.0.0"),
        .package(url: "https://github.com/0xLattice/cashew.git", exact: "5.0.3"),
    ],
    targets: [
        .executableTarget(name: "Interop", dependencies: [
            .product(name: "LatticePrimitives", package: "Lattice"),
            .product(name: "LatticeValidation", package: "Lattice"),
            .product(name: "Multikey", package: "Multikey"),
            .product(name: "cashew", package: "cashew"),
        ]),
    ]
)
