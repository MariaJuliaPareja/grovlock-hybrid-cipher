"""
cliente.py

Corre en cualquier otro dispositivo de la red. Recibe la IP del servidor
como argumento en la línea de comandos. Establece una conexión TCP y
ejecuta el handshake ECDH automáticamente (Sección III.D.1 del paper).

Uso:
    python cliente.py <ip_del_servidor>

NOTA DE RECONSTRUCCIÓN: igual que servidor.py, este archivo no aparece
como figura de código; se reconstruye siguiendo el flujo de 7 pasos
descrito en la Sección III.D.3 y el protocolo JSON de la Fig. 8.
"""

from __future__ import annotations

import json
import socket
import sys
import threading

from hybrid_cipher_v2 import SesionCifradoV2

PORT = 8888
SESION_ID_FIJO = 1337


def enviar_json(conn: socket.socket, obj: dict) -> None:
    conn.sendall((json.dumps(obj) + "\n").encode("utf-8"))


def leer_lineas(conn: socket.socket):
    buffer = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buffer += chunk
        while b"\n" in buffer:
            linea, buffer = buffer.split(b"\n", 1)
            if linea:
                yield json.loads(linea.decode("utf-8"))


def recibir_loop(conn: socket.socket, sesion: SesionCifradoV2) -> None:
    """
    Un hilo independiente escucha mensajes entrantes sin bloquear la
    entrada del usuario (paso 7 del flujo, Sección III.D.3).
    """
    try:
        for msg in leer_lineas(conn):
            if msg["tipo"] == "mensaje":
                texto_plano = sesion.descifrar_mensaje(msg["cifrado"])
                print(f"\n[Servidor] {texto_plano}\n> ", end="", flush=True)
    except Exception:
        pass


def main():
    if len(sys.argv) < 2:
        print("Uso: python cliente.py <ip_del_servidor>")
        sys.exit(1)

    ip_servidor = sys.argv[1]

    print("=" * 60)
    print(f"  GrovLock — Cliente TCP")
    print(f"  Conectando a {ip_servidor}:{PORT}...")
    print("=" * 60)

    # Paso 1: el cliente abre una conexión TCP al servidor
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((ip_servidor, PORT))

    sesion = SesionCifradoV2(str(SESION_ID_FIJO))

    # Paso 2: el cliente envía su clave pública X25519 en formato JSON
    enviar_json(conn, {"tipo": "handshake_pub", "pub_key": sesion.clave_publica_propia_b64})

    lineas = leer_lineas(conn)

    # Paso 3: el servidor responde con su propia clave pública
    respuesta = next(lineas)
    assert respuesta["tipo"] == "handshake_pub"

    # Paso 4: ambos completan el handshake con sesion_id=1337
    sesion.completar_handshake(respuesta["pub_key"])

    # Paso 5: espera handshake_ok
    ok_msg = next(lineas)
    assert ok_msg["tipo"] == "handshake_ok"
    print(f"[+] {ok_msg['msg']}")
    print(f"[+] Clave derivada: {sesion.clave_sesion.hex()[:12]}...")

    # Hilo para recibir mensajes sin bloquear (paso 7)
    hilo = threading.Thread(target=recibir_loop, args=(conn, sesion), daemon=True)
    hilo.start()

    print("Escribe mensajes y presiona Enter para enviarlos. 'salir' para terminar.\n")
    try:
        while True:
            texto = input("> ")
            if texto.strip().lower() == "salir":
                enviar_json(conn, {"tipo": "fin"})
                break
            # Paso 6: cada mensaje pasa por cifrar() antes de enviarse
            cifrado = sesion.cifrar_mensaje(texto)
            enviar_json(conn, {"tipo": "mensaje", "cifrado": cifrado})
    except KeyboardInterrupt:
        enviar_json(conn, {"tipo": "fin"})
    finally:
        conn.close()


if __name__ == "__main__":
    main()
