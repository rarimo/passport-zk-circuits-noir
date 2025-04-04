
import {decoded, Base64} from "./asn1.js"
import { poseidon } from "./poseidon.js";
import fs from 'fs';
import { createHash } from 'crypto';


const reHex = /^\s*(?:[0-9A-Fa-f][0-9A-Fa-f]\s*)+$/
function print(x){
    console.log(x)
}

function computeHash(outLen, input) {
    const hashAlgorithms = {
        20: 'sha1',
        28: 'sha224',
        32: 'sha256',
        48: 'sha384',
        64: 'sha512'
    };

    const algorithm = hashAlgorithms[outLen];
    if (!algorithm) {
        throw new Error("Invalid hash output length. Use 20, 28, 32, 48, or 64 bytes.");
    }

    const hash = createHash(algorithm).update(Buffer.from(input)).digest();
    return new Uint8Array(hash);
}

function bigintToArray(n, k, x) {
    const mod = BigInt(2) ** BigInt(n);
    let result = [];
    
    for (let i = 0; i < k; i++) {
        result.push(x % mod);
        x = x / mod; 
    }

    return result;
}

function compute_barret_reduction(n_bits, n){
    return BigInt(2) ** BigInt(2 * n_bits) / n
}


// SIGNATURE_TYPE:
//   - 1: RSA 2048 bits + SHA2-256 + e = 65537
//   - 2: RSA 4096 bits + SHA2-256 + e = 65537
//   - 3: RSA 2048 bits + SHA1 + e = 65537

//   - 10: RSASSA-PSS 2048 bits MGF1 (SHA2-256) + SHA2-256 + e = 3 + salt = 32
//   - 11: RSASSA-PSS 2048 bits MGF1 (SHA2-256) + SHA2-256 + e = 65537 + salt = 32
//   - 12: RSASSA-PSS 2048 bits MGF1 (SHA2-256) + SHA2-256 + e = 65537 + salt = 64
//   - 13: RSASSA-PSS 2048 bits MGF1 (SHA2-384) + SHA2-384 + e = 65537 + salt = 48
//   - 14: RSASSA-PSS 3072 bits MGF1 (SHA2-256) + SHA2-256 + e = 65537 + salt = 32

//   - 20: ECDSA brainpoolP256r1 + SHA256
//   - 21: ECDSA secp256r1 + SHA256
//   - 22: ECDSA brainpoolP320r1 + SHA256
//   - 23: ECDSA secp192r1 + SHA1

function getSigType(pk, sig, hashType){
    
    if (sig.salt){
        // RSA PSS
        if (pk.n.length == 512 && pk.exp == "3" && sig.salt == "32"&& hashType == "32"){
            return 10
        }
        if (pk.n.length == 512 && pk.exp == "10001" && sig.salt == "32"&& hashType == "32"){
            return 11
        }
        if (pk.n.length == 512 && pk.exp == "10001" && sig.salt == "64"&& hashType == "32"){
            return 12
        }
        if (pk.n.length == 512 && pk.exp == "10001" && sig.salt == "48" && hashType == "48"){
            return 13
        }
        if (pk.n.length == 768 && pk.exp == "10001" && sig.salt == "32" && hashType == "32"){
            return 14
        }
    }
    if (sig.salt == 0){
        // RSA
        if (pk.n.length == 512 && pk.exp == "10001" && hashType == "32"){
            return 1
        }
        if (pk.n.length == 1024 && pk.exp == "10001" && hashType == "32"){
            return 2
        }
        if (pk.n.length == 512 && pk.exp == "10001" && hashType == "20"){
            return 3
        }
    }
    if (sig.r){
        // print(pk.param);
        switch (pk.param){
            case "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9":
                // BrainpoolP256r1
                return 21
            
            case "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC":
                // Secp256r1
                return 20
        
            case "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826":
                // BrainpoolP384r1
                return 25

            case "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA":
                //BrainpoolP512r1
                return 26
            
            case "secp521r1":
                return 27
            default:
                return 0
        }
    }

    return 0
}

function hexStringToBytes(hexString) {
    hexString = hexString.replace(/\s+/g, '');
    
    const bytes = [];
    
    for (let i = 0; i < hexString.length; i += 2) {
      const byte = parseInt(hexString.substr(i, 2), 16);
      bytes.push(byte);
    }
    
    return bytes;
}

function readJsonFileSync(filePath) {
    try {
        const data = fs.readFileSync(filePath, 'utf8');
        const json = JSON.parse(data);
        return json
    } catch (error) {
        console.error('Error reading or parsing file:', error);
    }
}

function getFirstOctetString(asn1){
    // EC - first octet string of sod
    if (asn1.name === "OCTET_STRING") {
        return asn1;
    }
    
    // find first one with recursion
    if (Array.isArray(asn1.sub)) {
        for (let child of asn1.sub) {
            const result = getFirstOctetString(child);
            if (result) {
                return result;  
            }
        }
    }
}

function extract_encapsulated_content(asn1){
    const ec = getFirstOctetString(asn1);

    let hashType = ec.sub[0].sub[2].sub[0].sub[1].length
    

    return [ec.content, hashType]
}

function getDg1Shift(asn1, dg1, dgHashType){
    const ec = getFirstOctetString(asn1);
    const dg1Hash = computeHash(dgHashType, dg1);
    return ec.content.toLowerCase().split(Buffer.from(dg1Hash).toString('hex'))[0].length / 2
}

function getDg15Shift(asn1, dg15, dgHashType){
    const ec = getFirstOctetString(asn1);
    const dg15Hash = computeHash(dgHashType, dg15);
    return ec.content.toLowerCase().split(Buffer.from(dg15Hash).toString('hex'))[0].length / 2
}

function getEcShift(asn1, ec, hashType){
    let sa = getZero(asn1)
    const ecHash = computeHash(hashType, ec);

    return sa.dump.toLowerCase().split(Buffer.from(ecHash).toString('hex'))[0].length / 2
}

function getZero(asn1){

    if (!asn1) return null;
  
    // Check if this element is '[0]'
    if (asn1.name === '[0]') {

      // Check if it has a last 'sub' with 'SEQUENCE' and 'content' is "(2 elem)"
      if (asn1.sub && asn1.sub[asn1.sub?.length - 1]?.name === 'SEQUENCE' && asn1.sub[asn1.sub?.length - 1]?.content === '(2 elem)') {
        const sequenceSub = asn1.sub[asn1.sub?.length - 1].sub;
        
        // Check the first sub-element: it should be "OBJECT_IDENTIFIER"
        if (sequenceSub && sequenceSub[0]?.name === 'OBJECT_IDENTIFIER') {
          
          // Check the second sub-element: it should be "SET"
          if (sequenceSub[1]?.name === 'SET') {

            // Check if SET has only one sub-element with name "OCTET_STRING"
            if (sequenceSub[1]?.sub?.length === 1 && sequenceSub[1]?.sub[0]?.name === 'OCTET_STRING') {

              return asn1;  // Found the element that satisfies the condition
            }
          }
        }
      }
    }
    if (Array.isArray(asn1.sub)) {
        for (let child of asn1.sub) {
            const result = getZero(child);
            if (result) return result;  // Return the first match found
        }
    }
    
    return null;
}

function extract_signed_atributes(asn1) {
    let sa = getZero(asn1)

    const hashType = sa.sub.slice(-1)[0].sub.slice(-1)[0].sub[0].length

    return ["31" + sa.dump.slice(2), hashType]
}

function extract_signature(asn1){
    var [octet, parent] = findParentOfLastOctetString(asn1)
    const salt = parent.sub.slice(-2, -1)[0].sub.slice(-1)[0].sub?.slice(-1)[0].sub[0].content? parent.sub.slice(-2, -1)[0].sub.slice(-1)[0].sub.slice(-1)[0].sub[0].content : 0 
    if (octet.sub){
        // ECDSA SIG
        let sig = {r: BigInt(octet.sub[0].sub[0].content, 10).toString(16).toLowerCase(), s: BigInt(octet.sub[0].sub[1].content, 10).toString(16).toLowerCase()}
        return sig
    } else {
        return {n: octet.content, salt: salt}
    }
}

function findParentOfLastOctetString(asn1, parent = null) {
    let result = null;
    let lastParent = null;

    // If current element is an OCTET_STRING, update result and lastParent
    if (asn1.name === "OCTET_STRING") {
        result = asn1;
        lastParent = parent;
    }

    // Recursively search in sub-elements (if any)
    if (asn1.sub && Array.isArray(asn1.sub)) {
        for (let child of asn1.sub) {
            const [childResult, childParent] = findParentOfLastOctetString(child, asn1);
            if (childResult) {
                result = childResult;
                lastParent = childParent;
            }
        }
    }

    return [result, lastParent];
}

function get_ecdsa_key_location(asn1){
    // we want to get point and curve info
    if (asn1.sub && asn1.sub.length >= 2) {
        const secondChild = asn1.sub[1];
        if (secondChild.name === "BIT_STRING" && secondChild.content.startsWith("00000100")) {
            return asn1; // Return the element if the conditions are met
        }
    }

    // Recursively search in sub-elements (if any)
    if (asn1.sub && Array.isArray(asn1.sub)) {
        for (let child of asn1.sub) {
            const result = get_ecdsa_key_location(child);
            if (result) {
                return result; // Return the found element
            }
        }
    }

    return null; // Return null if no matching element is found
}

function extract_ecdsa_pubkey(asn1){
    const asn1_location = get_ecdsa_key_location(asn1)
    // console.log(asn1_location)

    let pubkey = asn1_location.sub[1].content.slice(8)
    let x = BigInt("0b" + pubkey.slice(0, pubkey.length / 2)).toString(16)
    let y = BigInt("0b" + pubkey.slice(pubkey.length / 2)).toString(16)

    // let curve_param = BigInt(asn1_location.sub[0].sub[1].sub.slice(-1)[0].content, 10).toString(16)
    
    let curve_param = asn1_location.sub[0].sub[1].sub? asn1_location.sub[0].sub[1].sub[2].sub[0].content : asn1_location.sub[0].sub[1].content.split("\n")[1]
    return {x: x, y: y, param: curve_param}
}

function get_rsa_key_location(asn1){

    if (asn1.name === "BIT_STRING" && Array.isArray(asn1.sub)) {
        
        // Look for the SEQUENCE child
        for (let child of asn1.sub) {
            if (child.name === "SEQUENCE" && Array.isArray(child.sub)) {
                
                // Check if SEQUENCE has exactly 2 children with the name "INTEGER"
                if (child.sub.length === 2 &&
                    child.sub[0].name === "INTEGER" &&
                    child.sub[1].name === "INTEGER") {
                    return asn1; // Return the BIT_STRING element
                }
            }
        }
    }

    // Recursively search through sub-elements
    if (asn1.sub && Array.isArray(asn1.sub)) {
        for (let child of asn1.sub) {
            const result = get_rsa_key_location(child);
            if (result) return result; // Return the found element
        }
    }

    return null; // Return null if no match is found
}

function extract_rsa_pubkey(asn1){
    const asn1_location = get_rsa_key_location(asn1)

    let pk = BigInt(asn1_location.sub[0].sub[0].content, 10).toString(16)
    let exp = BigInt(asn1_location.sub[0].sub[1].content, 10).toString(16)

    return {n: pk, exp: exp}
}

function extractFromDg15(dg15){
    if (!dg15) {
        return [0, 0, 0];
    }
    let dg15_decoded = decoded(dg15)
    let pk;
    let aa_shift = 0;
    let pk_type = dg15_decoded.sub[0].sub[1].content.slice(0,8) == "00000100" ? "ecdsa" : "rsa"
    let aa_sig_type = 0;

    if (pk_type == "ecdsa"){
        let pk_bit = dg15_decoded.sub[0].sub[1].content.slice(8)
        pk = {
            x: pk_bit.slice(0, pk_bit.length / 2),
            y: pk_bit.slice(pk_bit.length / 2)
        }
        const p = BigInt(dg15_decoded.sub[0].sub[0].sub[1].sub[4].content).toString(16).toLocaleUpperCase();

        switch (p){
            case "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7":
                { 
                    // brainpoolP256r1
                    aa_sig_type = 21;
                    break;
                }
            case "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF":
                { 
                    // secp256r1
                    aa_sig_type = 20;
                    break;
                }
            case "D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27":
                { 
                    // brainpool320r1
                    aa_sig_type = 22;
                    break;
                }
            case "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF":
                { 
                    // secp192r1
                    aa_sig_type = 23;
                    break;
                }
            default: 
                aa_sig_type = "unknown tech!";
        }
        aa_shift = dg15_decoded.dump.split(BigInt(`0b${pk.x}`).toString(16).toUpperCase())[0].length / 2
    } 
    if (pk_type == "rsa") {
        let pk_location = dg15_decoded.sub[0].sub[1].sub[0]
        let n = pk_location.sub[0].content
        let exp = pk_location.sub[1].content

        pk = {
            n: n,
            exp: exp
        }
        
        if (BigInt(pk.n).toString(16).length == 384){
            aa_sig_type = 3;
        }
        if (BigInt(pk.n).toString(16).length == 256){
            if (pk.exp.toString() == "3"){
                aa_sig_type = 2;
            } else {
                aa_sig_type = 1;
            }
        }
        aa_shift = dg15_decoded.dump.split(BigInt(pk.n).toString(16).toUpperCase())[0].length / 2
    }
    
    return [pk, aa_shift, aa_sig_type]

}

function getChunkedParams(pk, sig){
    const ec_field_size = pk.param? reHex.test(pk.param)? (pk.param.length * 4) : pk.param.match(/\d+/)? parseInt(pk.param.match(/\d+/)[0], 10): "UNKNOWN FIELD SIZE" : 0
    const chunk_number = pk.x ? Math.ceil(pk.x.length / 30) : Math.ceil(pk.n.length / 30)

    const pk_chunked = pk.x? (bigintToArray(120, chunk_number, BigInt("0x" + pk.x)).concat(bigintToArray(120, chunk_number, BigInt("0x" + pk.y)))) : bigintToArray(120, chunk_number, BigInt("0x" + pk.n))
    const sig_chunked = pk.x? (bigintToArray(120, chunk_number, BigInt("0x" + sig.r)).concat(bigintToArray(120, chunk_number, BigInt("0x" + sig.s)))) : bigintToArray(120, chunk_number, BigInt("0x" + sig.n))
    const reduction = pk.x? (bigintToArray(120, chunk_number * 2, BigInt(0))) : bigintToArray(120, chunk_number, compute_barret_reduction(pk.n.length * 4 + 2, BigInt("0x" + pk.n))) 

    return {
        ec_field_size: ec_field_size,
        chunk_number: ec_field_size != 0 ? chunk_number * 2 : chunk_number,
        pk_chunked: pk_chunked,
        sig_chunked: sig_chunked,
        reduction: reduction
    }
}

function getFakeIdenData(ec, pk){
    const branches = new Array(80).fill(0);
    const sk_iden = Buffer.from(computeHash(32, ec)).toString('hex').slice(0, 62);
    let pk_hash;
    if (pk.x){
        if (pk.x.length <= 62){ 
            pk_hash = poseidon([BigInt("0x" + pk.x), BigInt("0x" + pk.y)]);            
        } else {
            pk_hash = poseidon([BigInt("0x" + pk.x.slice(pk.x.length - 62)), BigInt("0x" + pk.y.slice(pk.y.length - 62))]);       
        }
    } else {
        let pk_arr = bigintToArray(64, 15, BigInt("0x" + pk.n))
        pk_hash = poseidon(Array.from({ length: 5 }, (_, i) => pk_arr[3 * i] * 2n ** 128n + pk_arr[3 * i + 1] * 2n ** 64n + pk_arr[3 * i + 2]));
    }

    const root = poseidon([pk_hash, pk_hash, 1n]).toString(16)

    return [sk_iden, root, branches]
}

function writeToNoir(inputs, params, name){
    const res_str = `//${name}\npub mod sigver;\npub mod big_curve;\npub mod rsa;\npub mod sha1;\npub mod sha224;\npub mod sha384;\npub mod rsa_pss;\npub mod jubjub;\npub mod smt;\npub mod utils;\nmod not_passports_zk_circuits;\nuse not_passports_zk_circuits::register_identity;\n\nfn main(\n\tdg1: [u8; ${params.dg1_len}],\n\tdg15: [u8; ${params.dg15_len}],\n\tec: [u8; ${params.ec_len}],\n\tsa: [u8; ${params.sa_len}],\n\tpk: [Field; ${params.n}],\n\treduction_pk: [Field; ${params.n}],\n\tsig: [Field; ${params.n}],\n\tsk_identity: Field,\n\ticao_root: pub Field,\n\tinclusion_branches: [Field; 80]) -> pub (Field, Field, Field, Field){\n\tlet tmp = register_identity::<\n\t\t${params.dg1_len},\n\t\t${params.dg15_len},\n\t\t${params.ec_len},\n\t\t${params.sa_len},\n\t\t${params.n},\n\t\t${params.ec_field_size},\n\t\t${params.dg_hash_type},\n\t\t${params.hash_type},\n\t\t${params.sig_type},\n\t\t${params.dg1_shift},\n\t\t${params.dg15_shift},\n\t\t${params.ec_shift},\n\t\t${params.aa_sig_type},\n\t\t${params.aa_shift}>(\n\tdg1, dg15, ec, sa, pk, reduction_pk, sig, sk_identity, icao_root, inclusion_branches);\n\t(tmp.0, tmp.1, tmp.2, tmp.3)\n}\n\n#[test]\nfn test_main(){\n\tprintln(main(\n\t\t${inputs.dg1},\n\t\t${inputs.dg15},\n\t\t${inputs.ec},\n\t\t${inputs.sa},\n\t\t${inputs.pk},\n\t\t${inputs.reduction},\n\t\t${inputs.sig},\n\t\t${inputs.sk_identity},\n\t\t${inputs.icao_root},\n\t\t${inputs.inclusion_branches}))\n}`
    fs.writeFile("../src/main.nr", res_str, "utf-8", Error);
}

function writeToToml(inputs){
    const res_str = `dg1=${inputs.dg1}\ndg15=${inputs.dg15}\nec=${inputs.ec}\nicao_root="${inputs.icao_root}"\ninclusion_branches=${inputs.inclusion_branches}\npk=${inputs.pk}\nreduction_pk=${inputs.reduction}\nsa=${inputs.sa}\nsig=${inputs.sig}\nsk_identity="${inputs.sk_identity}"`.replaceAll(",", `","`).replaceAll("[", `["`).replaceAll("]", `"]`).replace(`dg15=[""]`, "dg15=[]")
    fs.writeFile("../Prover.toml", res_str, "utf-8", Error);
}
function processPassport(filePath){
    // Extract json data
    const json = readJsonFileSync(filePath)

    // Get dg1 and dg15 from json
    const dg1_bytes  = json.dg1? reHex.test(json.dg1) ? Hex.decode(json.dg1) : Base64.unarmor(json.dg1) : [];
    const dg15_bytes = reHex.test(json.dg15) ? Hex.decode(json.dg15) : Base64.unarmor(json.dg15);
    
    // decode sod
    const asn1_decoded = decoded(json.sod)
    // get ec in hex and bytes
    const [ec_hex, dg_hash_type] = extract_encapsulated_content(asn1_decoded)
    const ec_bytes = hexStringToBytes(ec_hex)

    // get sa in hex and bytes
    const [sa_hex, hash_type] = extract_signed_atributes(asn1_decoded)
    const sa_bytes = hexStringToBytes(sa_hex)

    // get signature 
    const sig = extract_signature(asn1_decoded)
    
    // get ecdsa if r s in sig, else rsa
    const pk = (sig.salt || sig.salt == 0)? extract_rsa_pubkey(asn1_decoded) : extract_ecdsa_pubkey(asn1_decoded)
    // get sig algo
    const sigType = getSigType(pk, sig, hash_type);

    if (sigType == 0) print("UNKNOWN TECHONOLY");

    // get Shifts
    const dg1_shift = getDg1Shift(asn1_decoded, dg1_bytes, dg_hash_type);
    const ec_shift = getEcShift(asn1_decoded, ec_bytes, hash_type);
    const dg15_shift = dg15_bytes.length? getDg15Shift(asn1_decoded, dg15_bytes, dg_hash_type) : 0;

    // get dg15 info
    const [aa_pk, aa_shift, aa_sig_type] = extractFromDg15(json.dg15);

    const chunked = getChunkedParams(pk, sig)

    const [sk_iden, icao_root, branches] = getFakeIdenData(ec_bytes, pk)
    
    
    const inputs = {
        dg1: "[" + dg1_bytes.toString() + "]",
        dg15: dg15_bytes.length? "[" + dg15_bytes.toString() + "]" : "[]",
        ec: JSON.stringify(ec_bytes),
        sa: JSON.stringify(sa_bytes),
        pk: JSON.stringify(chunked.pk_chunked.map((x) => "0x" + x.toString(16))).replaceAll("\"", ""),
        reduction: JSON.stringify(chunked.reduction.map((x) => "0x" + x.toString(16))).replaceAll("\"", ""),
        sig: JSON.stringify(chunked.sig_chunked.map((x) => "0x" + x.toString(16))).replaceAll("\"", ""),
        sk_identity: "0x" + sk_iden.toString(16),
        icao_root: "0x" + icao_root.toString(16),
        inclusion_branches: JSON.stringify(branches)
    }

    const compile_params = {
        dg1_len: dg1_bytes.length,
        dg15_len: dg15_bytes.length,
        ec_len: ec_bytes.length,
        sa_len: sa_bytes.length,
        n: chunked.chunk_number,
        ec_field_size: chunked.ec_field_size,
        dg_hash_type: dg_hash_type,
        hash_type: hash_type,
        sig_type: sigType,
        dg1_shift: dg1_shift,
        dg15_shift: dg15_shift,
        ec_shift: ec_shift,
        aa_sig_type: aa_sig_type,
        aa_shift: aa_shift
    }

    const old_naming_convention = `registerIdentity_${compile_params.sig_type}_${dg_hash_type * 8}_${dg1_bytes.length == 93 ? 3 : 1}_${hash_type <= 32? Math.ceil((ec_bytes.length +8)/ 64) : Math.ceil((ec_bytes.length +8) / 128)}_${ec_shift*8}_${dg1_shift*8}_${dg15_bytes.length == 0? "NA" : (aa_sig_type) + "_" + dg15_shift * 8 + "_" + (dg_hash_type <= 32? Math.ceil((dg15_bytes.length + 8) / 64) : Math.ceil((dg15_bytes.length + 8) / 128)) + "_" + aa_shift * 8}`
    writeToNoir(inputs, compile_params, old_naming_convention);
    writeToToml(inputs);


}

processPassport("passport.json");