from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64, json, random, hashlib

app = FastAPI()

# ── CORS (autorise Firebase Hosting + local) ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── CLÉS ──
AES_KEY = hashlib.sha256(b"securechat-aes-key-2024").digest()   # 32 bytes
DES_KEY = hashlib.md5(b"securechat-des").digest()[:8]           # 8 bytes

# ── ELGAMAL ──
ELGAMAL_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74
ELGAMAL_G = 2
ELGAMAL_X = 987654321098765432109876543210   # clé privée
ELGAMAL_Y = pow(ELGAMAL_G, ELGAMAL_X, ELGAMAL_P)


# ── CHIFFREMENT ──

def encrypt_aes(plaintext: str) -> dict:
    iv = get_random_bytes(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    return {
        "algo": "AES-CBC-256",
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ct).decode()
    }

def decrypt_aes(data: dict) -> str:
    iv = base64.b64decode(data["iv"])
    ct = base64.b64decode(data["ciphertext"])
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode("utf-8")


def encrypt_des(plaintext: str) -> dict:
    iv = get_random_bytes(8)
    cipher = DES.new(DES_KEY, DES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode("utf-8"), DES.block_size))
    return {
        "algo": "DES-CBC",
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ct).decode()
    }

def decrypt_des(data: dict) -> str:
    iv = base64.b64decode(data["iv"])
    ct = base64.b64decode(data["ciphertext"])
    cipher = DES.new(DES_KEY, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), DES.block_size).decode("utf-8")


def encrypt_elgamal(plaintext: str) -> dict:
    P, G, Y = ELGAMAL_P, ELGAMAL_G, ELGAMAL_Y
    k = random.randint(2, P - 2)
    c1 = pow(G, k, P)
    s = pow(Y, k, P)
    encrypted_bytes = [(byte * s) % P for byte in plaintext.encode("utf-8")]
    return {
        "algo": "ElGamal",
        "c1": str(c1),
        "c2_list": [str(x) for x in encrypted_bytes]
    }

def decrypt_elgamal(data: dict) -> str:
    P, X = ELGAMAL_P, ELGAMAL_X
    c1 = int(data["c1"])
    s = pow(c1, X, P)
    s_inv = pow(s, P - 2, P)
    decrypted = [int(c2) * s_inv % P for c2 in data["c2_list"]]
    return bytes(decrypted).decode("utf-8")


ENCRYPTORS = {
    "AES":     (encrypt_aes,     decrypt_aes),
    "DES":     (encrypt_des,     decrypt_des),
    "ElGamal": (encrypt_elgamal, decrypt_elgamal),
}


# ── GESTIONNAIRE WEBSOCKET ──
class ConnectionManager:
    def __init__(self):
        self.connections: list[dict] = []

    async def connect(self, ws: WebSocket, username: str):
        await ws.accept()
        self.connections.append({"ws": ws, "username": username})

    def disconnect(self, ws: WebSocket):
        self.connections = [c for c in self.connections if c["ws"] != ws]

    async def broadcast(self, msg: dict):
        dead = []
        for c in self.connections:
            try:
                await c["ws"].send_json(msg)
            except Exception:
                dead.append(c)
        for d in dead:
            self.connections.remove(d)

    def usernames(self):
        return [c["username"] for c in self.connections]


manager = ConnectionManager()


@app.get("/")
def root():
    return {"status": "SecureChat backend running"}


@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    await manager.connect(websocket, username)
    await manager.broadcast({
        "type": "system",
        "text": f"{username} a rejoint le salon",
        "users": manager.usernames()
    })
    try:
        while True:
            data = await websocket.receive_json()
            plaintext = data.get("text", "")
            algo = data.get("algo", "AES")
            if algo not in ENCRYPTORS:
                algo = "AES"

            encrypt_fn, decrypt_fn = ENCRYPTORS[algo]
            encrypted = encrypt_fn(plaintext)
            decrypted_check = decrypt_fn(encrypted)

            await manager.broadcast({
                "type": "message",
                "from": username,
                "plaintext": plaintext,
                "encrypted": encrypted,
                "decrypted": decrypted_check,
                "algo": algo,
                "timestamp": data.get("timestamp", ""),
                "uid": data.get("uid", "")
            })
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        await manager.broadcast({
            "type": "system",
            "text": f"{username} a quitté le salon",
            "users": manager.usernames()
        })