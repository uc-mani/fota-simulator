import os

def generate_firmware(version, size_kb=50):
    print("generate_firmware \n")
    with open(f"firmware/v{version}.bin", "wb") as f:
        f.write(os.urandom(size_kb * 1024))

generate_firmware(1)
generate_firmware(2)
