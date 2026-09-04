#!/usr/bin/env python3
"""
Regenerate noir register_identity mains for every RSA verifier, deriving the
exact generics from (a) the compiled ACIR ABI shipped in the GitHub releases
and (b) the verifier name. No passport corpus needed.

  ABI  (release .json)  -> DG1_LEN, DG15_LEN, EC_LEN, SA_LEN, N
  name (verifier .sol)  -> SIG_TYPE, DG_HASH_ALGO, EC_SHIFT, DG1_SHIFT, AA...
  SIG_TYPE map          -> HASH_ALGO (content hash)
  EC_FIELD_SIZE = 0 (RSA)

For each variant it writes  <out>/<name>/src/main.nr .  Then, per variant:
  cp -r that package, nargo compile, bb write_vk, bb contract -> Verifier.sol.

Coverage note: HASH_ALGO comes from getSigType (types 1,2,3,10,11,12,13,14).
Types 6,7,8,15 are not in the checked-out getSigType -> HASH_ALGO is inferred
from (SA_LEN - EC_SHIFT) and FLAGGED; confirm those against the real variant.
"""
import json, re, glob, os, sys, urllib.request

CT = sys.argv[1] if len(sys.argv) > 1 else "../passport-contracts"
OUT = sys.argv[2] if len(sys.argv) > 2 else "regen_out"
MAP = "noir_acir_map.json"  # {argstring: [tag, url]} built by the coverage step

# content-hash (bytes) per SIG_TYPE, authoritative from getSigType()
HASH_ALGO = {1: 32, 2: 32, 3: 20, 10: 32, 11: 32, 12: 32, 13: 48, 14: 32}
RSA = {1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15}

def fetch_abi(url):
    req = urllib.request.Request(url, headers={"User-Agent": "x", "Range": "bytes=0-262143"})
    s = urllib.request.urlopen(req, timeout=60).read().decode("utf-8", "replace")
    # brace-match the "abi" object (robust to pretty-printing), string-aware
    j = s.index("{", s.index('"abi"'))
    depth, instr, esc = 0, False, False
    for k in range(j, len(s)):
        c = s[k]
        if instr:
            esc = (c == "\\") and not esc
            if c == '"' and not esc:
                instr = False
        elif c == '"':
            instr = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return json.loads(s[j:k + 1])["parameters"]
    raise ValueError("abi object not fully within fetched range")

def alen(params, name):
    for p in params:
        if p["name"] == name:
            return p["type"].get("length", 0)
    return 0

def decode_name(args):
    t = args.split("_")
    sig, dghash8, doc, ecb, ecs8, d1s8 = t[:6]
    r = dict(sig_type=int(sig), dg_hash_algo=int(dghash8) // 8,
             ec_shift=int(ecs8) // 8, dg1_shift=int(d1s8) // 8,
             aa_sig_type=0, dg15_shift=0, aa_shift=0)
    if t[6] != "NA":
        r.update(aa_sig_type=int(t[6]), dg15_shift=int(t[7]) // 8, aa_shift=int(t[9]) // 8)
    return r

def main():
    m = json.load(open(MAP))
    rows, flagged = [], []
    for args, (tag, url) in sorted(m.items()):
        n = decode_name(args)
        ps = fetch_abi(url)
        dg1, dg15, ec, sa, N = (alen(ps, k) for k in ("dg1", "dg15", "ec", "sa", "pk"))
        if n["sig_type"] in HASH_ALGO:
            ha, src = HASH_ALGO[n["sig_type"]], "map"
        else:
            cand = sa - n["ec_shift"]
            ha, src = (cand, "sa-ecshift?") if cand in (20, 32, 48, 64) else (None, "UNKNOWN")
        if ha is None:
            flagged.append((args, f"sa={sa} ec_shift={n['ec_shift']}")); continue
        if src != "map":
            flagged.append((args, f"HASH_ALGO={ha} via {src} -> VERIFY"))
        g = [dg1, dg15, ec, sa, N, 0, n["dg_hash_algo"], ha, n["sig_type"],
             n["dg1_shift"], n["dg15_shift"], n["ec_shift"], n["aa_sig_type"], n["aa_shift"]]
        d = f"{OUT}/registerIdentity_{args}/src"
        os.makedirs(d, exist_ok=True)
        open(f"{d}/main.nr", "w").write(
            f"//registerIdentity_{args}\n"
            "use noir_dl::not_passports_zk_circuits::register_identity;\n\n"
            f"fn main(\n\tdg1: [u8; {dg1}],\n\tdg15: [u8; {dg15}],\n\tec: [u8; {ec}],\n\tsa: [u8; {sa}],\n"
            f"\tpk: [Field; {N}],\n\treduction_pk: [Field; {N}],\n\tsig: [Field; {N}],\n"
            "\tsk_identity: Field,\n\ticao_root: Field,\n\tinclusion_branches: [Field; 80])"
            " -> pub (Field, Field, Field, Field, Field){\n"
            f"\tlet tmp = register_identity::<{', '.join(map(str, g))}>(\n"
            "\tdg1, dg15, ec, sa, pk, reduction_pk, sig, sk_identity, icao_root, inclusion_branches);\n"
            "\t(tmp.0, tmp.1, tmp.2, tmp.3, icao_root)\n}\n")
        rows.append(args)
    print(f"generated {len(rows)} noir mains in {OUT}/")
    if flagged:
        print(f"\n{len(flagged)} need manual HASH_ALGO confirmation:")
        for a, why in flagged:
            print("  ", a, "->", why)

if __name__ == "__main__":
    main()
