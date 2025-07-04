# 🔄 FOTA Simulator for IoT Devices

This project simulates the complete **Firmware-Over-The-Air (FOTA)** update process for IoT devices, including:
- Delta firmware updates using `bsdiff4`
- Device-side patching and SHA-256 integrity verification
- Power Loss Recovery (PLR) to resume interrupted updates
- Flask-based firmware update server
- Optional simulated crash using `--plr` flag

> ⚡️ MQTT-based update command system will be added in a future revision.

---

## 📌 Why This Project?

In real-world embedded systems and IoT deployments, FOTA is essential for:
- Updating firmware securely and efficiently
- Avoiding full firmware downloads (especially on cellular/low-bandwidth devices)
- Ensuring updates can survive interruptions (e.g. power loss)

This simulator replicates all of that in Python to demonstrate core FOTA concepts.

---

## 🧱 Project Structure

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


