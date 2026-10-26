"""Safe self-test trigger for RDRS.

Creates throwaway files inside data/sandbox, then overwrites them with
random bytes and renames them with a .locked extension - mimicking the
observable signature of ransomware (mass rename + high entropy) without
using any real malware or touching anything outside the sandbox folder.

Run the monitor first, then run this script in a second terminal:
    python -m app.main --watch ./data/sandbox
    python scripts/simulate_attack.py
"""
import os
import pathlib
import shutil
import time

sandbox = pathlib.Path("data/sandbox")
if sandbox.exists():
    shutil.rmtree(sandbox)
sandbox.mkdir(parents=True, exist_ok=True)

print(f"Creating 50 normal files in {sandbox}/ ...")
for i in range(50):
    (sandbox / f"file_{i}.txt").write_text("normal document content")

time.sleep(1)

print("Simulating an attack: overwriting with random bytes and renaming ...")
for f in list(sandbox.glob("*.txt")):
    f.write_bytes(os.urandom(20000))  # high-entropy, looks encrypted
    f.rename(f.with_suffix(".locked"))  # mass extension change

print("Done. Check the dashboard / /alerts endpoint for a Critical score.")
