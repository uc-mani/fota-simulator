import bsdiff4
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

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

def sign_firmware(firmware_path, private_key_path, sig_out_path):
    with open(firmware_path, "rb") as f:
        firmware_data = f.read()

    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    signature = private_key.sign(
        firmware_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
     )

    with open(sig_out_path, "wb") as sig_file:
        sig_file.write(signature)

generate_delta("firmware/v1.bin", "firmware/v2.bin", "updates/v1_to_v2.delta")
generate_sha256("firmware/v2.bin", "updates/v2.sha256")
sign_firmware("firmware/v2.bin", "keys/private_key.pem", "updates/v2.sig")