# 🔄 FOTA Simulator for IoT Devices

This project simulates the complete **Firmware-Over-The-Air (FOTA)** update process for IoT devices, including:
- Delta firmware updates using `bsdiff4`
- Device-side patching and SHA-256 integrity verification
- Power Loss Recovery (PLR) to resume interrupted updates
- Flask-based firmware update server
- Optional simulated crash using `--plr` flag

> ⚡️ MQTT-based update command system will be added in a future revision.


## 📌 Why This Project?

In real-world embedded systems and IoT deployments, FOTA is essential for:
- Updating firmware securely and efficiently
- Avoiding full firmware downloads (especially on cellular/low-bandwidth devices)
- Ensuring updates can survive interruptions (e.g. power loss)

This simulator replicates all of that in Python to demonstrate core FOTA concepts.

---

## 🧱 Project Structure
```
fota-simulator/
├── client/ # Device simulation
│ ├── apply_patch.py # Simple patching script
│ ├── device.py # FOTA client with PLR + hash check
│ └── base_firmware.bin # Original firmware on the device
├── server/
│ ├── app.py # Flask server for patch + hash files
│ └── generate_delta.py # Create delta and hash
├── firmware/ # Raw firmware files (v1 = old, v2 = updated)
├── updates/ # Generated patch and hash files
├── logs/ # PLR recovery logs
├── requirements.txt
└── README.md
```



---

## 🧰 Requirements

- Python 3.7+
- pip
- Optional: Mosquitto (for future MQTT feature)

Install dependencies:
```bash
pip install -r requirements.txt
```


## 🚀 Step-by-Step Usage

### ✅ 1. Generate Simulated Firmware Files
```
# Optional script if you want to regenerate firmware binaries
import os

def generate_firmware(version, size_kb=50):
    with open(f"firmware/v{version}.bin", "wb") as f:
        f.write(os.urandom(size_kb * 1024))

generate_firmware(1)
generate_firmware(2)
```

### ✅ 2. Generate Delta Patch and SHA-256
```
cd server
python generate_delta.py
```
This will create:
- updates/v1_to_v2.delta
- updates/v2.sha256

### ✅ 3. Start Flask Update Server
```
python app.py
```
Flask serves firmware updates and hashes:
- http://localhost:8000/updates/v1_to_v2.delta
- http://localhost:8000/hash/v2.sha256

### ✅ 4. Simulate Device Receiving Update
Run once to apply the patch fully:

```
cd ../
copy firmware\v1.bin client\base_firmware.bin
python client/apply_patch.py
```

You should get:

```
Patch downloaded.
Firmware updated successfully!
```

### ✅ 5. Simulate Power Loss Recovery (PLR)
```
python client/device.py --plr
```
Output:

```
Fetching delta update...
Applying patch...
Error during patch: Simulated power loss
Device crashed. Recovery info saved.
```

Then resume:
```
python client/device.py
```

You should see:
```
Applying patch...
Firmware verified successfully.
```

## 🔒 Firmware Validation
After applying the patch, the device verifies the new firmware’s hash against the SHA-256 provided by the server.

If valid → update is complete

If failed → rollback or retry (to be added in future)


![Diagram](https://github.com/user-attachments/assets/176cf900-3a6d-42c0-ba3b-af21236c71a4)




## 📜 License
MIT License

