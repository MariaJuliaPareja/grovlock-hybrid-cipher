"""
HybridECDH-Grover-AES — Versión 2.0

Fase 1 — ECDH X25519       : intercambio de claves
Fase 2 — KDF personalizada : derivación SHA-256 cascada
Fase 3 — Difusor de Grover : difusión cuántica simulada
Fase 4 — AES-256-GCM       : cifrado autenticado

NOTA DE RECONSTRUCCIÓN:
Las clases/funciones `ParDeClaves`, `kdf_propio`, `generar_nonce`, `cifrar`
y `descifrar` están transcritas literalmente de las Fig. 2-7 del paper.
La operación `secreto_ecdh = self._par.clave_privada.exchange(pub_remota)`
(Fig. 3) se integra aquí dentro de una clase `SesionCifradoV2` que el paper
menciona (usada por `session_manager.py`) pero cuyo cuerpo completo no se
muestra como figura — su estructura general se reconstruye a partir de
cómo se usa en el texto (Sección III.B.2: "genera automáticamente un par
de claves X25519 compuesto por una clave privada y una clave pública").
"""

from __future__ import annotations

import base64
import hashlib
import os
import struct
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as AESGCM

from grover_layer import aplicar_grover, revertir_grover

# ---------------------------------------------------------------------
# FASE 1: CLAVES ECDH (X25519 / Curva25519)
# ---------------------------------------------------------------------

SALT = b"grovlock-salt-fija"                 # placeholder: en el paper no se
SALT_PERSONALIZADO = b"grovlock-personalizado"  # detalla el valor exacto de sal
VERSION_PROTOCOLO = b"\x02"                  # "Versión 2.0" según Fig. 12


class ParDeClaves:
    def __init__(self):
        self.clave_privada = X25519PrivateKey.generate()
        self.clave_publica = self.clave_privada.public_key()

    def exportar_publica_b64(self) -> str:
        raw = self.clave_publica.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode()

    @staticmethod
    def importar_publica(b64: str) -> X25519PublicKey:
        raw = base64.b64decode(b64)
        return X25519PublicKey.from_public_bytes(raw)


# ---------------------------------------------------------------------
# FASE 2: KDF PERSONALIZADA
# ---------------------------------------------------------------------

def kdf_propio(secreto: bytes, contador: int) -> bytes:
    """
    SHA256( secreto || SALT || SHA256( contador || timestamp ) )
    Produce 32 bytes -> clave AES-256.
    """
    ts_bytes = struct.pack(">Q", int(time.time()))
    cnt_bytes = struct.pack(">Q", contador)
    inner = hashlib.sha256(cnt_bytes + ts_bytes).digest()
    return hashlib.sha256(secreto + SALT_PERSONALIZADO + inner).digest()


def generar_nonce(contador: int) -> bytes:
    """SHA256( microsegundos || contador || random )[:12]"""
    ts = struct.pack(">Q", int(time.time() * 1_000_000))
    cnt = struct.pack(">Q", contador)
    rnd = os.urandom(4)
    return hashlib.sha256(ts + cnt + rnd).digest()[:12]


# ---------------------------------------------------------------------
# FASE 3 + FASE 4: CIFRAR / DESCIFRAR (Grover + AES-256-GCM)
# ---------------------------------------------------------------------

def cifrar(clave: bytes, mensaje: str, contador: int) -> str:
    # Fase 3: capa Grover
    datos_planos = mensaje.encode("utf-8")
    datos_grover = aplicar_grover(datos_planos, clave)

    # Fase 4: AES-256-GCM
    nonce = generar_nonce(contador)
    aesgcm = AESGCM(clave)
    cifrado = aesgcm.encrypt(nonce, datos_grover, associated_data=None)

    # Empaquetar: versión(1) + nonce(12) + ciphertext+tag
    paquete = VERSION_PROTOCOLO + nonce + cifrado
    return base64.b64encode(paquete).decode()


def descifrar(clave: bytes, b64_texto: str) -> str:
    paquete = base64.b64decode(b64_texto)

    version = paquete[:1]
    nonce = paquete[1:13]
    cifrado = paquete[13:]

    # Fase 4 inversa: AES-GCM
    aesgcm = AESGCM(clave)
    datos_grover = aesgcm.decrypt(nonce, cifrado, associated_data=None)

    # Fase 3 inversa: revertir Grover
    datos_planos = revertir_grover(datos_grover, clave)
    return datos_planos.decode("utf-8")


# ---------------------------------------------------------------------
# Sesión de cifrado de extremo a extremo (usada por session_manager.py)
# RECONSTRUCCIÓN: estructura inferida de su uso en el paper, no de una
# figura de código específica.
# ---------------------------------------------------------------------

class SesionCifradoV2:
    """
    Encapsula el par de claves X25519 de un participante y, una vez
    completado el handshake, el secreto ECDH derivado y el contador de
    mensajes (necesario para la unicidad de los nonces de AES-GCM, según
    la Sección III.A.2 del paper).
    """

    def __init__(self, owner_id: str):
        self.owner_id = owner_id
        self._par = ParDeClaves()
        self.clave_publica_propia_b64 = self._par.exportar_publica_b64()
        self.clave_sesion: bytes | None = None
        self.contador_mensajes: int = 0

    def completar_handshake(self, pub_remota_b64: str) -> bytes:
        """
        Ejecuta ECDH con la clave pública remota y deriva la clave de
        sesión de 256 bits mediante kdf_propio(). Corresponde al flujo
        descrito en la Sección III.B.4 ("Intercambio ECDH y derivación
        de clave").
        """
        pub_remota = ParDeClaves.importar_publica(pub_remota_b64)
        secreto_ecdh = self._par.clave_privada.exchange(pub_remota)
        self.clave_sesion = kdf_propio(secreto_ecdh, contador=0)
        return self.clave_sesion

    def cifrar_mensaje(self, mensaje: str) -> str:
        if self.clave_sesion is None:
            raise RuntimeError("Handshake no completado: no hay clave de sesión.")
        self.contador_mensajes += 1
        return cifrar(self.clave_sesion, mensaje, self.contador_mensajes)

    def descifrar_mensaje(self, b64_texto: str) -> str:
        if self.clave_sesion is None:
            raise RuntimeError("Handshake no completado: no hay clave de sesión.")
        return descifrar(self.clave_sesion, b64_texto)
