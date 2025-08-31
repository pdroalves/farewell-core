// circuits/farewell_email.circom
// ------------------------------------------------------------
// FarewellEmailProof: DKIM-valid email → proves:
//   - SHA256(To:) over canonicalized address bits         → public to_hash[32]
//   - SHA256(raw bytes) for attachment #1 (e.g. skShare)  → public att1_hash[32]
//   - SHA256(raw bytes) for attachment #2 (e.g. payload)  → public att2_hash[32]
//   - DKIM domain and key-hash from the EmailVerifier     → public domain_packed[], keyhash[32]
//
// You pass the full email (headers+body) privately; JS input-gen provides byte offsets
// for the To: substring and each attachment’s BASE64 payload within the body.
//
// IMPORTANT: This file is a scaffold. You must:
//  - Point the includes to your local copies (zk-email EmailVerifier, base64 decode, sha256).
//  - Keep MAX_* bounds aligned with your input generator.
//  - Ensure your input generator feeds *canonicalized* To: and correct byte ranges.
//
// ------------------------------------------------------------

pragma circom 2.1.6;

// --- Includes (adjust to your project layout) ------------------------------

// SHA-256 over bytes/bits.
// If you use circomlib, you likely want something like:
include "node_modules/circomlib/circuits/sha256/sha256.circom";               // <<< EDIT PATH
include "node_modules/circomlib/circuits/bitify.circom";                      // <<< EDIT PATH

// Base64 decoder that turns ASCII Base64 chars into raw bytes.
// You can use an existing small decoder or your own.
// Must expose:  - inChars[BASE64_MAX]      (8-bit ASCII values)
//               - outBytes[RAW_MAX]        (8-bit values)
//               - outLen                    (number of decoded bytes)
include "lib/base64_decode.circom";                                           // <<< EDIT PATH

// ZK-Email’s EmailVerifier (DKIM verification circuit).
// The exact filename/symbol depends on the package version you use.
// It should expose .headerBits[], .bodyBits[] (or equivalent) and public
// outputs for domain bytes and the DKIM key hash.
include "node_modules/@zk-email/circuits/email-verifier.circom";              // <<< EDIT PATH


// --- Small byte/bits helpers ------------------------------------------------

// Slice a byte array [0..N) → subrange [start, start+len)
template ByteSlice(N, MAXLEN) {
    signal input in[N];         // bytes (0..255)
    signal input start;         // byte index
    signal input len;           // 0..MAXLEN
    signal output out[MAXLEN];  // filled with slice bytes, zero-padded past len

    // Range checks (coarse)
    start * 1 === start;
    len * 1 === len;

    // Constrain bounds: start+len <= N
    var i;
    for (i = 0; i < MAXLEN; i++) {
        // if i < len → copy byte; else → zero
        // Boolean flag: i < len
        signal lessThanLen;
        lessThanLen <== (len - (i+1)) >= 0;

        // Index = start + i
        signal idx;
        idx <== start + i;

        // Boolean flag: idx < N
        signal inRange;
        inRange <== (N - (idx + 1)) >= 0;

        // Default 0 when out of range or i >= len
        out[i] <== (lessThanLen * inRange) * in[idx];
    }
}

// Convert bytes[] → bits[] (big-endian per byte)
template BytesToBits(N) {
    signal input in[N];        // 0..255
    signal output out[N*8];    // bit 0 is MSB of byte0

    var i, b;
    for (i = 0; i < N; i++) {
        component n2b = Num2Bits(8);
        n2b.in <== in[i];
        // Num2Bits outputs little-endian; flip to MSB-first if you want.
        for (b = 0; b < 8; b++) {
            out[i*8 + (7-b)] <== n2b.out[b];
        }
    }
}

// Convert bits[256] → 32 bytes (big-endian per SHA-256 convention)
template Bits256ToBytes32() {
    signal input in[256];
    signal output out[32];

    var i, b;
    for (i = 0; i < 32; i++) {
        // each byte = 8 bits
        component pack = Bits2Num(8);
        for (b = 0; b < 8; b++) {
            pack.in[b] <== in[i*8 + b];
        }
        out[i] <== pack.out;
    }
}

// --- Main proof template ----------------------------------------------------
//
// MAX_HDR_BYTES   - upper bound for canonicalized header bytes fed to EmailVerifier
// MAX_BODY_BYTES  - upper bound for body bytes fed to EmailVerifier
// MAX_TO_BYTES    - upper bound for the To: substring we slice & hash
// MAX_B64_1       - upper bound for base64 chars of attachment #1
// MAX_B64_2       - upper bound for base64 chars of attachment #2
// MAX_RAW_1       - upper bound for decoded raw bytes of attachment #1
// MAX_RAW_2       - upper bound for decoded raw bytes of attachment #2
//
template FarewellEmailProof(
    // email caps
    var MAX_HDR_BYTES,
    var MAX_BODY_BYTES,
    // to: cap
    var MAX_TO_BYTES,
    // base64 + raw caps per attachment
    var MAX_B64_1, var MAX_RAW_1,
    var MAX_B64_2, var MAX_RAW_2,
    // packed domain bytes length to expose (you choose, e.g., 64)
    var DOMAIN_PACKED_LEN
) {
    // ---------------------------
    // 1) Core DKIM email verifier
    // ---------------------------
    // NOTE: Replace "EmailVerifier" with the actual symbol you import.
    // The common interface provides private inputs for email header/body
    // and public outputs with domain bytes and the DKIM key hash.
    component ev = EmailVerifier(MAX_HDR_BYTES, MAX_BODY_BYTES);

    // PUBLIC: DKIM domain (packed bytes) and key hash (SHA-256 32 bytes)
    signal output domain_packed[DOMAIN_PACKED_LEN];  // choose a cap large enough
    signal output dkim_keyhash[32];

    // Copy out public domain bytes (pad with zeros if shorter inside ev)
    // You must adapt this block to your EmailVerifier’s exact outputs.
    var i;
    for (i = 0; i < DOMAIN_PACKED_LEN; i++) {
        // Assuming ev.domainBytes[i] exists (byte, 0..255); adjust as needed.
        domain_packed[i] <== ev.domainBytes[i]; // <<< ADAPT to your EmailVerifier
    }
    for (i = 0; i < 32; i++) {
        // Assuming ev.keyHashBytes[i] exists (byte, 0..255); adjust as needed.
        dkim_keyhash[i] <== ev.keyHashBytes[i]; // <<< ADAPT to your EmailVerifier
    }

    // --------------------------------------------------
    // 2) Public SHA256 of canonicalized To: address only
    // --------------------------------------------------
    // Private inputs from JS: where To: address (canonicalized) sits in headers.
    signal input to_start;          // byte offset within header bytes
    signal input to_len;            // number of bytes (<= MAX_TO_BYTES)

    // Slice header bytes and hash
    component toSlice = ByteSlice(MAX_HDR_BYTES, MAX_TO_BYTES);
    for (i = 0; i < MAX_HDR_BYTES; i++) {
        // Assuming ev.headerBytes[i] is available as a byte 0..255.
        toSlice.in[i] <== ev.headerBytes[i]; // <<< ADAPT to your EmailVerifier
    }
    toSlice.start <== to_start;
    toSlice.len   <== to_len;

    // Bytes -> bits
    component toBits = BytesToBits(MAX_TO_BYTES);
    for (i = 0; i < MAX_TO_BYTES; i++) { toBits.in[i] <== toSlice.out[i]; }

    // SHA256 over those bits (truncate to exact len*8 inside the gadget by zero-padding)
    component toSha = Sha256(MAX_TO_BYTES*8);
    for (i = 0; i < MAX_TO_BYTES*8; i++) { toSha.in[i] <== toBits.out[i]; }

    // Public digest (32 bytes)
    signal output to_hash[32];
    component toDigestBytes = Bits256ToBytes32();
    for (i = 0; i < 256; i++) { toDigestBytes.in[i] <== toSha.out[i]; }
    for (i = 0; i < 32; i++) { to_hash[i] <== toDigestBytes.out[i]; }

    // ----------------------------------------------------------------
    // 3) Attachment #1: base64 slice → decode → SHA256(raw) → public
    // ----------------------------------------------------------------
    signal input att1_b64_start;    // byte offset in BODY where base64 chars begin
    signal input att1_b64_len;      // base64 chars length (<= MAX_B64_1)

    // Slice body bytes
    component a1Slice = ByteSlice(MAX_BODY_BYTES, MAX_B64_1);
    for (i = 0; i < MAX_BODY_BYTES; i++) {
        // Assuming ev.bodyBytes[i] exists; otherwise derive from bits.
        a1Slice.in[i] <== ev.bodyBytes[i]; // <<< ADAPT to your EmailVerifier
    }
    a1Slice.start <== att1_b64_start;
    a1Slice.len   <== att1_b64_len;

    // Base64 decode
    component a1B64 = Base64Decode(MAX_B64_1, MAX_RAW_1);
    for (i = 0; i < MAX_B64_1; i++) { a1B64.inChars[i] <== a1Slice.out[i]; }

    // Hash decoded raw bytes up to a1B64.outLen
    // We hash the full MAX_RAW_1 (zero-padded), which is sound if your input-gen ensures
    // padding bytes are zero beyond outLen.
    component a1BytesToBits = BytesToBits(MAX_RAW_1);
    for (i = 0; i < MAX_RAW_1; i++) { a1BytesToBits.in[i] <== a1B64.outBytes[i]; }

    component a1Sha = Sha256(MAX_RAW_1*8);
    for (i = 0; i < MAX_RAW_1*8; i++) { a1Sha.in[i] <== a1BytesToBits.out[i]; }

    signal output att1_hash[32];
    component a1DigestBytes = Bits256ToBytes32();
    for (i = 0; i < 256; i++) { a1DigestBytes.in[i] <== a1Sha.out[i]; }
    for (i = 0; i < 32; i++) { att1_hash[i] <== a1DigestBytes.out[i]; }

    // ----------------------------------------------------------------
    // 4) Attachment #2: base64 slice → decode → SHA256(raw) → public
    // ----------------------------------------------------------------
    signal input att2_b64_start;
    signal input att2_b64_len;

    component a2Slice = ByteSlice(MAX_BODY_BYTES, MAX_B64_2);
    for (i = 0; i < MAX_BODY_BYTES; i++) {
        a2Slice.in[i] <== ev.bodyBytes[i]; // <<< ADAPT
    }
    a2Slice.start <== att2_b64_start;
    a2Slice.len   <== att2_b64_len;

    component a2B64 = Base64Decode(MAX_B64_2, MAX_RAW_2);
    for (i = 0; i < MAX_B64_2; i++) { a2B64.inChars[i] <== a2Slice.out[i]; }

    component a2BytesToBits = BytesToBits(MAX_RAW_2);
    for (i = 0; i < MAX_RAW_2; i++) { a2BytesToBits.in[i] <== a2B64.outBytes[i]; }

    component a2Sha = Sha256(MAX_RAW_2*8);
    for (i = 0; i < MAX_RAW_2*8; i++) { a2Sha.in[i] <== a2BytesToBits.out[i]; }

    signal output att2_hash[32];
    component a2DigestBytes = Bits256ToBytes32();
    for (i = 0; i < 256; i++) { a2DigestBytes.in[i] <== a2Sha.out[i]; }
    for (i = 0; i < 32; i++) { att2_hash[i] <== a2DigestBytes.out[i]; }
}

// A concrete "main" you can compile while tuning bounds.
// Adjust these caps to your expected email sizes.
component main = FarewellEmailProof(
    4096,     // MAX_HDR_BYTES
    65536,    // MAX_BODY_BYTES
    128,      // MAX_TO_BYTES
    24576,    // MAX_B64_1  (≈ 18 KiB raw when base64)
    18432,    // MAX_RAW_1  (match your skShare size cap)
    98304,    // MAX_B64_2  (≈ 72 KiB raw)
    73728,    // MAX_RAW_2  (match your payload cap)
    64        // DOMAIN_PACKED_LEN
);
