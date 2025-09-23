# main.py
import base64
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Optional, Literal, List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

# ========= Config =========
# 1) Спробувати взяти шлях з ENV (для macOS/Homebrew: export OPENSSL_BIN=$(brew --prefix openssl@3)/bin/openssl)
# 2) Інакше взяти з PATH
# 3) Як останній шанс — типовий шлях Homebrew (Apple Silicon / Intel)
OPENSSL_BIN = (
    os.environ.get("OPENSSL_BIN")
    or shutil.which("openssl")
    or "/opt/homebrew/opt/openssl@3/bin/openssl"
)

STATE_DIR = Path("./state")
KEYS_DIR = STATE_DIR / "keys"
CERTS_DIR = STATE_DIR / "certs"
STATE_DIR.mkdir(exist_ok=True)
KEYS_DIR.mkdir(exist_ok=True)
CERTS_DIR.mkdir(exist_ok=True)

# ========= Models =========
class KeyGenRequest(BaseModel):
    algo: Literal["RSA", "ECDSA", "Ed25519"] = "RSA"
    keySize: int = Field(2048, ge=2048, description="For RSA only")
    curve: str = Field("secp256r1", description="For ECDSA only")
    protection: Literal["PKCS12"] = "PKCS12"  # HSM mock omitted in lab proto
    label: str = "signing-key-01"
    subject: str = "CN=Demo User,O=Org,C=UA"
    exportCert: bool = True
    pkcs12_password: str = Field("changeit", min_length=4)

class KeyGenResponse(BaseModel):
    keyId: str
    certId: Optional[str] = None
    publicKeyPem: Optional[str] = None
    certificatePem: Optional[str] = None

class SignRequest(BaseModel):
    keyId: str
    signMode: Literal["attached", "detached"] = "attached"
    hashAlg: Literal["SHA256", "SHA384", "SHA512"] = "SHA256"
    content: str = Field(..., description="base64-encoded bytes")

class SignResponse(BaseModel):
    cms: str  # base64 CMS
    format: str = "application/pkcs7-signature"
    signMode: Literal["attached", "detached"]

class VerifyRequest(BaseModel):
    cms: str  # base64 CMS
    detachedContent: Optional[str] = None  # base64-encoded bytes

class SignerInfo(BaseModel):
    subject: Optional[str] = None
    serialNumber: Optional[str] = None
    alg: Optional[str] = None
    time: Optional[str] = None
    chainValid: bool = False
    revocation: str = "unchecked"

class VerifyResponse(BaseModel):
    isValid: bool
    signers: List[SignerInfo] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)

# ========= Helpers =========
def run(cmd: list[str], input_bytes: bytes | None = None) -> bytes:
    try:
        proc = subprocess.run(
            cmd,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return proc.stdout
    except subprocess.CalledProcessError as e:
        err = e.stderr.decode(errors="ignore").strip()
        raise HTTPException(status_code=400, detail=f"OpenSSL error: {err or e}")

def ensure_openssl():
    try:
        out = run([OPENSSL_BIN, "version"]).decode().strip()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OpenSSL not available: {e}")
    if "OpenSSL 3" not in out:
        # На macOS часто стоїть LibreSSL → треба встановити openssl@3 і передати шлях через ENV
        raise HTTPException(
            status_code=500,
            detail=f"Need OpenSSL 3.x. Detected: '{out}'. "
                   f"Install via Homebrew and set OPENSSL_BIN, e.g.: "
                   f"export OPENSSL_BIN=$(brew --prefix openssl@3)/bin/openssl"
        )

def b64decode_to_file(b64: str, path: Path):
    try:
        data = base64.b64decode(b64)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 in 'content' or 'cms'.")
    path.write_bytes(data)
    return path

def file_to_b64(path: Path) -> str:
    return base64.b64encode(path.read_bytes()).decode()

def key_paths(key_id: str) -> dict:
    return {
        "priv_pem": KEYS_DIR / f"{key_id}.key.pem",
        "pub_pem": KEYS_DIR / f"{key_id}.pub.pem",
        "cert_pem": CERTS_DIR / f"{key_id}.crt.pem",
        "p12": KEYS_DIR / f"{key_id}.p12",
    }

# ========= App =========
app = FastAPI(title="Signature Service (Lab)", version="1.0")

@app.on_event("startup")
def _startup():
    ensure_openssl()

@app.get("/")
def root():
    return {
        "status": "ok",
        "message": "Сервер працює. Дивись інтерактивну документацію на /docs",
        "docs": "/docs"
    }

# ---- /v1/keys/generate ----
@app.post("/v1/keys/generate", response_model=KeyGenResponse, status_code=201)
def generate_keys(req: KeyGenRequest):
    key_id = f"k_{uuid.uuid4().hex[:8]}"
    paths = key_paths(key_id)

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        priv = td / "priv.pem"
        pub = td / "pub.pem"
        csr = td / "req.csr"
        cert = td / "cert.pem"

        # 1) Private key
        if req.algo == "RSA":
            run([OPENSSL_BIN, "genpkey", "-algorithm", "RSA",
                 "-pkeyopt", f"rsa_keygen_bits:{req.keySize}", "-out", str(priv)])
        elif req.algo == "ECDSA":
            run([OPENSSL_BIN, "genpkey", "-algorithm", "EC",
                 "-pkeyopt", f"ec_paramgen_curve:{req.curve}", "-out", str(priv)])
        elif req.algo == "Ed25519":
            run([OPENSSL_BIN, "genpkey", "-algorithm", "ED25519", "-out", str(priv)])
        else:
            raise HTTPException(400, "Unsupported algo")

        # 2) Public key
        run([OPENSSL_BIN, "pkey", "-in", str(priv), "-pubout", "-out", str(pub)])

        # 3) Self-signed cert (lab)
        subj = "/" + req.subject.replace(",", "/").replace(" ", "")
        run([OPENSSL_BIN, "req", "-new", "-subj", subj, "-key", str(priv), "-out", str(csr)])
        run([OPENSSL_BIN, "x509", "-req", "-in", str(csr), "-signkey", str(priv),
             "-days", "365", "-out", str(cert)])

        # 4) Save artifacts
        KEYS_DIR.mkdir(exist_ok=True, parents=True)
        CERTS_DIR.mkdir(exist_ok=True, parents=True)
        shutil.copy2(priv, paths["priv_pem"])
        shutil.copy2(pub, paths["pub_pem"])
        shutil.copy2(cert, paths["cert_pem"])

        # 5) PKCS#12 (password-protected)
        run([
            OPENSSL_BIN, "pkcs12", "-export",
            "-inkey", str(paths["priv_pem"]),
            "-in", str(paths["cert_pem"]),
            "-name", req.label,
            "-out", str(paths["p12"]),
            "-passout", f"pass:{req.pkcs12_password}"
        ])

    return KeyGenResponse(
        keyId=key_id,
        certId=key_id,
        publicKeyPem=paths["pub_pem"].read_text(),
        certificatePem=paths["cert_pem"].read_text() if req.exportCert else None,
    )

# ---- /v1/sign ----
@app.post("/v1/sign", response_model=SignResponse)
def sign(req: SignRequest):
    paths = key_paths(req.keyId)
    if not paths["priv_pem"].exists() or not paths["cert_pem"].exists():
        raise HTTPException(404, f"keyId {req.keyId} not found")

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        content_file = td / "content.bin"
        cms_out = td / "signature.p7s"

        b64decode_to_file(req.content, content_file)

        cmd = [
            OPENSSL_BIN, "cms", "-sign",
            "-binary",
            "-in", str(content_file),
            "-signer", str(paths["cert_pem"]),
            "-inkey", str(paths["priv_pem"]),
            "-outform", "DER",
            "-out", str(cms_out),
            "-md", req.hashAlg.lower()
        ]
        # Правильні прапорці:
        # attached: -nodetach; detached: -detached
        if req.signMode == "attached":
            cmd.append("-nodetach")
        else:
            cmd.append("-detached")

        run(cmd)
        return SignResponse(
            cms=file_to_b64(cms_out),
            signMode=req.signMode,
        )

# ---- /v1/verify ----
@app.post("/v1/verify", response_model=VerifyResponse)
def verify(req: VerifyRequest):
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        cms_in = td / "sig.p7s"
        data_in = td / "data.bin"
        out_content = td / "out.bin"

        b64decode_to_file(req.cms, cms_in)

        verify_cmd = [OPENSSL_BIN, "cms", "-verify", "-binary",
                      "-inform", "DER", "-in", str(cms_in), "-out", str(out_content)]

        if req.detachedContent:
            b64decode_to_file(req.detachedContent, data_in)
            verify_cmd += ["-content", str(data_in)]

        # Лабораторний режим: ланцюг довіри не перевіряємо (лише коректність підпису)
        verify_cmd += ["-noverify", "-no_attr_verify"]

        warnings: List[str] = []
        try:
            run(verify_cmd)
            is_valid = True
        except HTTPException as e:
            is_valid = False
            warnings.append(str(e.detail))

        # best-effort витягти деякі дані про підписанта
        signers: List[SignerInfo] = []
        try:
            txt = run([OPENSSL_BIN, "cms", "-cmsout", "-inform", "DER",
                       "-in", str(cms_in), "-print"]).decode(errors="ignore")
            subj = None
            alg = None
            for line in txt.splitlines():
                l = line.strip()
                if "issuerAndSerialNumber" in l and "CN=" in l:
                    # дуже грубий парсер — цього досить для лабораторної
                    subj = l.split("CN=")[-1].split(",")[0].strip()
                if "digestAlgorithm" in l and "(" in l:
                    alg = l.split("(")[-1].rstrip(")")
            signers.append(SignerInfo(
                subject=subj or "Unknown",
                serialNumber="N/A",
                alg=alg or "sha256WithRSAEncryption",
                time=None,
                chainValid=False,
                revocation="unchecked",
            ))
        except Exception:
            pass

        return VerifyResponse(isValid=is_valid, signers=signers, warnings=warnings)
