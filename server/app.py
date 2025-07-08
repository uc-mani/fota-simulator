from flask import Flask, send_from_directory

app = Flask(__name__)
@app.route("/firmware/<path:filename>")
def serve_firmware(filename):
    return send_from_directory("../firmware", filename)

@app.route("/updates/<path:filename>")
def serve_updates(filename):
    return send_from_directory("../updates", filename)

@app.route("/hash/<path:filename>")
def serve_hash(filename):
    return send_from_directory("../updates", filename)

@app.route("/sig/<path:filename>")
def serve_sig(filename):
    return send_from_directory("../updates", filename)


if __name__ == "__main__":
    app.run(port=8000)
