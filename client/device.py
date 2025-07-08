import shutil
import requests
import bsdiff4
import os
import hashlib
import argparse
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes


# === File Paths and URLs ===
BASE_FW = "client/base_firmware.bin"  # Original firmware
BACKUP_FW = "client/firmware_backup.bin"  # Backup in case of rollback
PATCH_FILE = "client/patch.delta"  # Delta patch to apply
NEW_FW = "client/firmware.bin"  # Resulting firmware after patch
RECOVERY_LOG = "logs/recovery.log"  # Used to resume after crash
HASH_URL = "http://localhost:8000/hash/v2.sha256"  # Expected hash from server
PATCH_URL = "http://localhost:8000/updates/v1_to_v2.delta"  # Delta patch URL
SIG_URL = "http://localhost:8000/sig/v2.sig"  # Signature of the new firmware
PUBKEY_PATH = "keys/public_key.pem"  # Public key for signature verification

# === MQTT Configuration ===
MQTT_BROKER = "localhost"
MQTT_TOPIC = "device/update"  # Topic to receive update triggers
MQTT_STATUS_TOPIC = "device/status"  # Topic to publish update status


# === Command Line Argument for Power Loss Simulation ===
# run on CLI like: python client/device.py --plr
parser = argparse.ArgumentParser()
parser.add_argument("--plr", action="store_true", help="Simulate power loss during patch")
args = parser.parse_args()
SIMULATE_PLR = args.plr

# === Download the patch file from server ===
def download_patch():
    print("Fetching delta update...")
    r = requests.get(PATCH_URL)
    if r.status_code == 200:
        with open(PATCH_FILE, "wb") as f:
            f.write(r.content)
        print("Patch downloaded.")
    else:
        print("Failed to fetch patch.")
        return False
    return True

# === Apply delta patch to base firmware ===
def apply_patch_with_recovery():
    print("Applying patch...")
    try:
        if os.path.exists(BASE_FW):
            shutil.copy(BASE_FW, BACKUP_FW)  # Backup base firmware
            print("Backup created.")

        with open(BASE_FW, "rb") as f_old, open(PATCH_FILE, "rb") as f_patch:
            old_data = f_old.read()
            patch_data = f_patch.read()

        if SIMULATE_PLR:
            raise Exception("Simulated power loss")  # Crash simulation

        new_data = bsdiff4.patch(old_data, patch_data) #diff old and patch data, to get new data(v2)
        with open(NEW_FW, "wb") as f_new:
            f_new.write(new_data) # writes new data to firmware.bin

############# ----  FW ROLLBACK SIMULATION  ---- ##############
        # Simulate corruption
        #with open(NEW_FW, "ab") as f:
            #f.write(b"corruption")
############# ----  FW ROLLBACK SIMULATION  ---- ##############

        if os.path.exists(RECOVERY_LOG):
            os.remove(RECOVERY_LOG)  # Clear recovery log if successful

        print("Patch applied successfully.")
        return True

    except Exception as e:
        print("Error during patch:", e)
        with open(RECOVERY_LOG, "w") as log:
            log.write("Patch failed\n")
        return False

# === Verify firmware using SHA256 hash ===
def verify_firmware():
    print("Verifying firmware integrity...")
    try:
        r = requests.get(HASH_URL)
        if r.status_code != 200:
            print("Could not fetch expected SHA256.")
            return False
        expected = r.text.strip()

        sha256 = hashlib.sha256()
        with open(NEW_FW, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                sha256.update(block)

        actual = sha256.hexdigest()
        if actual == expected:
            print("Firmware verified successfully.")
            return True
        else:
            print("Firmware verification failed!")
            return False
    except Exception as e:
        print("Error during verification:", e)
        return False

# === Verify firmware signature using RSA ===
def verify_signature():
    try:
        print("Verifying firmware signature...")

        # load firmware
        with open(NEW_FW, "rb") as f:
            firmware_data = f.read()

        # Load public key
        with open(PUBKEY_PATH, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        # Download Signature
        r = requests.get(SIG_URL)
        if r.status_code != 200:
            print("Failed to download firmware signature.")
            return False

        signature = r.content

        # Verify signature
        public_key.verify(
            signature,
            firmware_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        print("Signature Verified Successfully.")
        return True

    except Exception as e:
        print("Signature verification failed!", e)
        return False

# === Handle MQTT message callback ===
def on_message(client, userdata, msg):
    payload = msg.payload.decode().strip().lower()
    print(f"[MQTT] Received command: {payload}")

    if payload == "start":
        print("[MQTT] Starting firmware update process.")

        # Begin update logic
        if not os.path.exists(PATCH_FILE) or os.path.exists(RECOVERY_LOG):
            if not download_patch():
                client.publish(MQTT_STATUS_TOPIC, "download_failed")
                return

        if apply_patch_with_recovery():
            if verify_firmware():
                if verify_signature():
                    print("Firmware verified successfully.")
                    client.publish(MQTT_STATUS_TOPIC, "Update_success")
                else:
                    print("Signature invalid. Performing rollback.")
                    client.publish(MQTT_STATUS_TOPIC, "signature_invalid")
                    if os.path.exists(BACKUP_FW):
                        shutil.copy(BACKUP_FW, NEW_FW)
                        print("Rollback complete. Previous firmware restored.")
                        client.publish(MQTT_STATUS_TOPIC, "rollback_performed")
                    else:
                        print("Rollback failed: backup not found.")
                        client.publish(MQTT_STATUS_TOPIC, "rollback_failed")

            else:
                print("Update corrupted — performing rollback.")
                if os.path.exists(BACKUP_FW):
                    shutil.copy(BACKUP_FW, NEW_FW)
                    print("Rollback complete. Previous firmware restored.")
                    client.publish(MQTT_STATUS_TOPIC, "rollback_performed")
                else:
                    print("Rollback failed: backup not found.")
                    client.publish(MQTT_STATUS_TOPIC, "rollback_failed")

        else:
            print("Device crashed. Recovery info saved.")
            client.publish(MQTT_STATUS_TOPIC, "patch_failed")

# === Start MQTT listener ===
def start_mqtt_listener():
    global client
    client = mqtt.Client()
    client.on_message = on_message
    client.connect(MQTT_BROKER)
    client.subscribe(MQTT_TOPIC)
    print(f"Subscribed to MQTT topic: {MQTT_TOPIC}")
    client.loop_forever()

if __name__ == "__main__":
    start_mqtt_listener()