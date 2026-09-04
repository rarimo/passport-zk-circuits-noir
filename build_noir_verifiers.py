#!/usr/bin/env python3
"""
Build one Solidity verifier per generated main.nr.

Input : regen_out/registerIdentity_<args>/src/main.nr   (from regen_noir.py)
Output: regen_out/sol/NoirRegisterIdentity_<args>.sol    (drop-in verifiers)

For each variant it swaps the main into the register_identity package and runs:
    nargo compile
    bb write_vk -b target/register_identity.json -o target/vk
    bb contract -k target/vk -b target/register_identity.json -o target/Verifier.sol
then renames the bb contract (UltraVerifier) to NoirRegisterIdentity_<args>.

Safe to re-run: variants whose .sol already exists are skipped. The package's
own src/main.nr is backed up and restored at the end.

Usage:
    python3 build_noir_verifiers.py [--only SUBSTR] [--limit N] [--pkg register_identity]
"""
import os, re, sys, shutil, subprocess, argparse, glob

REPO = os.path.dirname(os.path.abspath(__file__))

def run(cmd, cwd, timeout):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or "") + (p.stderr or "")

def variant_name(main_path):
    # first line is  //registerIdentity_<args>
    first = open(main_path).readline().strip()
    m = re.match(r"//\s*registerIdentity_(.+)$", first)
    if not m:
        raise ValueError(f"no //registerIdentity_ header in {main_path}")
    return m.group(1)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mains", default=os.path.join(REPO, "regen_out"))
    ap.add_argument("--out", default=os.path.join(REPO, "regen_out", "sol"))
    ap.add_argument("--pkg", default="register_identity")
    ap.add_argument("--only", default="", help="build only variants whose args contain this substring")
    ap.add_argument("--limit", type=int, default=0, help="build at most N variants (0 = all)")
    ap.add_argument("--timeout", type=int, default=900)
    a = ap.parse_args()

    pkg = os.path.join(REPO, a.pkg)
    acir = os.path.join(pkg, "target", "register_identity.json")
    vk = os.path.join(pkg, "target", "vk")
    ver = os.path.join(pkg, "target", "Verifier.sol")
    main_dst = os.path.join(pkg, "src", "main.nr")
    os.makedirs(a.out, exist_ok=True)

    mains = sorted(glob.glob(os.path.join(a.mains, "registerIdentity_*", "src", "main.nr")))
    if a.only:
        mains = [m for m in mains if a.only in m]
    if a.limit:
        mains = mains[:a.limit]

    backup = main_dst + ".bak"
    shutil.copy(main_dst, backup)
    ok, fail, skip = [], [], []
    try:
        for i, mp in enumerate(mains, 1):
            name = variant_name(mp)
            out_sol = os.path.join(a.out, f"NoirRegisterIdentity_{name}.sol")
            # release assets: ACIR + verification key, named as in the GitHub releases
            out_acir = os.path.join(a.out, f"registerIdentity_{name}.json")
            out_vk = os.path.join(a.out, f"registerIdentity_{name}.vk")
            if all(os.path.exists(p) for p in (out_sol, out_acir, out_vk)):
                skip.append(name); print(f"[{i}/{len(mains)}] skip (exists) {name}"); continue
            print(f"[{i}/{len(mains)}] {name}")
            shutil.copy(mp, main_dst)
            broke = False
            for step, cmd in (
                ("nargo compile", ["nargo", "compile"]),
                ("bb write_vk", ["bb", "write_vk", "-b", acir, "-o", vk]),
                ("bb contract", ["bb", "contract", "-k", vk, "-b", acir, "-o", ver]),
            ):
                rc, log = run(cmd, pkg, a.timeout)
                if rc != 0 or (step == "bb contract" and not os.path.exists(ver)):
                    killed = rc in (-9, 137, -6, 134, 139)
                    hint = "  <- KILLED (likely OOM: circuit too big for this machine's RAM)" if killed else ""
                    tail = log.strip().splitlines()[-15:]
                    fail.append((name, f"{step} rc={rc}", tail))
                    print(f"    FAIL @ {step} rc={rc}{hint}")
                    if len(fail) == 1:  # show full output of the first failure to diagnose
                        print("    ---- nargo/bb output ----")
                        print(("    " + "\n    ".join(tail)) if tail else "    (no output — process was killed by a signal)")
                        print("    -------------------------")
                    broke = True
                    break
            if broke:
                continue
            else:
                src = open(ver).read().replace(
                    "contract UltraVerifier is BaseUltraVerifier",
                    f"contract NoirRegisterIdentity_{name} is BaseUltraVerifier")
                open(out_sol, "w").write(src)
                # nargo/bb overwrite target/ on every iteration, so keep a per-variant
                # copy of the ACIR and the verification key -- both are release assets.
                shutil.copy(acir, out_acir)
                shutil.copy(vk, out_vk)
                vkh = next((l for l in src.splitlines() if "Verification Key Hash" in l), "")
                ok.append(name); print(f"    OK -> {os.path.relpath(out_sol, REPO)}  {vkh.strip()}")
    finally:
        shutil.move(backup, main_dst)

    print(f"\n=== done: {len(ok)} ok, {len(fail)} failed, {len(skip)} skipped ===")
    for name, step, tail in fail:
        print(f"  FAIL {name} @ {step}: {' | '.join(tail)}")

if __name__ == "__main__":
    main()
