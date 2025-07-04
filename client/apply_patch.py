import requests
import bsdiff4
import os

BASE_FW = "client/base_firmware.bin"
PATCH_FILE = "client/patch.delta"
OUTPUT_FW = "client/firmware.bin"

# Download patch from server
def download_patch():
    print("Downloading patch...")
    url = "http://localhost:8000/updates/v1_to_v2.delta"
    r = requests.get(url)
    if r.status_code == 200:
        with open(PATCH_FILE, "wb") as f:
            f.write(r.content)
        print("Patch downloaded.")
    else:
        print("Failed to download patch.")
        exit(1)

# Apply patch to generate new firmware
def apply_patch():
    print("Applying patch to base firmware...")
    with open(BASE_FW, "rb") as f_old, open(PATCH_FILE, "rb") as f_patch:
        new_fw = bsdiff4.patch(f_old.read(), f_patch.read())
    with open(OUTPUT_FW, "wb") as f_new:
        f_new.write(new_fw)
    print("Firmware updated successfully!")

if __name__ == "__main__":
    download_patch()
    apply_patch()
