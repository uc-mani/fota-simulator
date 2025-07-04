import bsdiff4
import hashlib

def generate_delta(old_path, new_path, delta_path):
    with open(old_path, "rb") as f_old, open(new_path, "rb") as f_new:
        delta = bsdiff4.diff(f_old.read(), f_new.read())
    with open(delta_path, "wb") as f_delta:
        f_delta.write(delta)

def generate_sha256(file_path, out_path):
    sha256_hash = hashlib.sha256()
    with open(file_path,"rb") as f:
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    with open(out_path, "w") as out:
        out.write(sha256_hash.hexdigest())

generate_delta("firmware/v1.bin", "firmware/v2.bin", "updates/v1_to_v2.delta")
generate_sha256("firmware/v2.bin", "updates/v2.sha256")
