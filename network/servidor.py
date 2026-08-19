"""
servidor.py

Corre en la laptop. Escucha en todas las interfaces de red (0.0.0.0) en
el puerto 8888. Al iniciar detecta automáticamente la IP local WiFi y la
muestra. Acepta múltiples clientes con un hilo por conexión
(Sección III.D.1 del paper).

NOTA DE RECONSTRUCCIÓN: este archivo no aparece como figura de código en
el paper (solo se describe en prosa, Secciones III.D.1 y III.D.3, y el
protocolo JSON de la Fig. 8, transcrito aquí de forma literal). Se
reconstruye siguiendo esos 7 pasos de handshake y el formato de mensajes.
"""

from __future__ import annotations

import json
import socket
import threading

from hybrid_cipher_v2 import SesionCifradoV2

HOST = "0.0.0.0"
PORT = 8888
SESION_ID_FIJO = 1337  # según el paper: "usando el mismo sesion_id=1337"


def obtener_ip_local() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


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


def manejar_cliente(conn: socket.socket, addr) -> None:
    print(f"[+] Cliente conectado: {addr}")
    sesion = SesionCifradoV2(str(SESION_ID_FIJO))

    try:
        lineas = leer_lineas(conn)

        # Paso 2: el cliente envía su clave pública X25519 en formato JSON
        primer_msg = next(lineas)
        assert primer_msg["tipo"] == "handshake_pub"
        pub_cliente = primer_msg["pub_key"]

        # Paso 3: el servidor responde con su propia clave pública X25519
        enviar_json(conn, {"tipo": "handshake_pub", "pub_key": sesion.clave_publica_propia_b64})

        # Paso 4: ambos llaman a completar_handshake() con la clave recibida
        sesion.completar_handshake(pub_cliente)

        # Paso 5: el servidor envía handshake_ok
        enviar_json(conn, {"tipo": "handshake_ok", "msg": "Sesion cifrada establecida"})
        print(f"[+] Sesión cifrada establecida con {addr}")

        # Paso 6-7: cada mensaje pasa por descifrar()/cifrar()
        for msg in lineas:
            if msg["tipo"] == "mensaje":
                texto_plano = sesion.descifrar_mensaje(msg["cifrado"])
                print(f"[{addr}] {texto_plano}")

                respuesta = f"Servidor recibió: {texto_plano}"
                cifrado_resp = sesion.cifrar_mensaje(respuesta)
                enviar_json(conn, {"tipo": "mensaje", "cifrado": cifrado_resp})
            elif msg["tipo"] == "fin":
                print(f"[-] Cliente {addr} cerró la sesión.")
                break

    except (ConnectionResetError, StopIteration):
        print(f"[-] Cliente {addr} desconectado.")
    finally:
        conn.close()


def main():
    ip_local = obtener_ip_local()
    print("=" * 60)
    print("  GrovLock — Servidor TCP")
    print(f"  Escuchando en {HOST}:{PORT}")
    print(f"  IP local WiFi detectada: {ip_local}")
    print(f"  Los clientes deben conectarse a: {ip_local}:{PORT}")
    print("=" * 60)

    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((HOST, PORT))
    servidor.listen()

    try:
        while True:
            conn, addr = servidor.accept()
            hilo = threading.Thread(target=manejar_cliente, args=(conn, addr), daemon=True)
            hilo.start()
    except KeyboardInterrupt:
        print("\n[!] Servidor detenido.")
    finally:
        servidor.close()


if __name__ == "__main__":
    main()
