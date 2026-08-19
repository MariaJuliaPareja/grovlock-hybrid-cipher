<details open>
<summary><h2>🇬🇧 English</h2></summary>

# GrovLock

GrovLock is a hybrid cryptographic scheme designed to protect telematic communications. It combines X25519 (ECDH) for secure key exchange, a SHA-256 based key derivation function for session keys, a diffusion layer inspired by Grover's diffusion operator, and AES-256-GCM for authenticated encryption.

Authors: Alegre Castilla, Sthefany Alexandra; Espino Veas, Karla Daniela; Panclas Aliaga, Maria Claudia; Pareja Abarca, Maria Julia. Universidad Catolica de Santa Maria (UCSM), 2026.

Current status: in active improvement. The team is working on optimizing and correcting the implementation, including the diffusion layer fix described below.

Paper (draft / preprint): [GrovLock_EN_draft.pdf](./paper/GrovLock_EN_draft.pdf)

## About the diffusion layer

During testing, the diffusion layer (the module that applies a Grover inspired reflection to each 128 bit block before AES encryption) was found to have a correctness issue: the reflection constant was being derived from the block's own data using integer division, which only guarantees exact reversibility under a specific mathematical condition that does not hold for arbitrary input. Empirically, this caused most messages to fail to decrypt correctly.

The fix now derives the reflection constant from the session key instead of the block's data, and reverses the rounds in the correct order when decrypting. A reflection with a fixed constant is always its own exact inverse regardless of the constant used, so this guarantees perfect reversibility for any input while preserving the key dependent diffusion the design calls for. This was verified against 2000 randomized test cases with zero failures, plus edge cases (empty messages, long messages, accented characters, emoji).

## Project structure

- `hybrid_cipher_v2.py`: key pair generation (X25519), key derivation function, nonce generation, encrypt/decrypt functions, and the session class that ties the handshake to the cipher.
- `grover_layer.py`: the diffusion layer described above.
- `session_manager.py`: tracks active sessions, pending connection requests, and derived keys between users.
- `bot.py`: Telegram bot exposing the protocol through chat commands.
- `servidor.py` / `cliente.py`: a TCP/IP client-server implementation of the same protocol over a local network.

## Usage

```bash
pip install -r requirements.txt

# Local TCP chat
python servidor.py
python cliente.py <server_ip>

# Telegram bot (requires a TOKEN environment variable)
export TOKEN="your_botfather_token"
python bot.py
```

The cryptographic core (`hybrid_cipher_v2.py` and `grover_layer.py`) is tested and functional. `servidor.py`, `cliente.py`, and `bot.py` follow the protocol as designed but have not yet been re-tested against a live Telegram instance or a real network deployment.

If you find something to fix or want to propose an improvement, open an Issue or a Pull Request. Any of the authors can review and merge.

</details>

<details>
<summary><h2>🇪🇸 Español</h2></summary>

# GrovLock

GrovLock es un esquema criptografico hibrido disenado para proteger comunicaciones telematicas. Combina X25519 (ECDH) para el intercambio seguro de claves, una funcion de derivacion de claves basada en SHA-256 para las claves de sesion, una capa de difusion inspirada en el operador de difusion de Grover, y AES-256-GCM para el cifrado autenticado.

Autoras: Alegre Castilla, Sthefany Alexandra; Espino Veas, Karla Daniela; Panclas Aliaga, Maria Claudia; Pareja Abarca, Maria Julia. Universidad Catolica de Santa Maria (UCSM), 2026.

Estado actual: en mejora activa. El equipo esta trabajando en optimizar y corregir la implementacion, incluyendo la correccion de la capa de difusion detallada abajo.

Paper (borrador / preprint): [GrovLock_ES_borrador.pdf](./paper/GrovLock_ES_borrador.pdf)

## Sobre la capa de difusion

Durante las pruebas se encontro un problema de correctitud en la capa de difusion (el modulo que aplica una reflexion inspirada en Grover a cada bloque de 128 bits antes del cifrado AES): la constante de reflexion se derivaba de los propios datos del bloque usando division entera, lo cual solo garantiza invertibilidad exacta bajo una condicion matematica especifica que no se cumple para datos arbitrarios. En la practica, esto hacia que la mayoria de los mensajes fallaran al descifrarse.

La correccion deriva ahora la constante de reflexion a partir de la clave de sesion en vez de los datos del bloque, y revierte las rondas en el orden correcto al descifrar. Una reflexion con una constante fija es siempre su propia inversa exacta sin importar el valor de esa constante, lo que garantiza invertibilidad perfecta para cualquier dato, preservando a la vez la dependencia de la clave que el diseno buscaba. Esto se verifico contra 2000 casos de prueba aleatorios sin ningun fallo, ademas de casos borde (mensajes vacios, mensajes largos, caracteres con tildes, emojis).

## Estructura del proyecto

- `hybrid_cipher_v2.py`: generacion de pares de claves (X25519), funcion de derivacion de claves, generacion de nonce, funciones de cifrar/descifrar, y la clase de sesion que conecta el handshake con el cifrado.
- `grover_layer.py`: la capa de difusion descrita arriba.
- `session_manager.py`: administra las sesiones activas, solicitudes de conexion pendientes y claves derivadas entre usuarios.
- `bot.py`: bot de Telegram que expone el protocolo mediante comandos de chat.
- `servidor.py` / `cliente.py`: implementacion cliente-servidor TCP/IP del mismo protocolo sobre una red local.

## Uso

```bash
pip install -r requirements.txt

# Chat TCP local
python servidor.py
python cliente.py <ip_del_servidor>

# Bot de Telegram (requiere la variable de entorno TOKEN)
export TOKEN="tu_token_de_botfather"
python bot.py
```

El nucleo criptografico (`hybrid_cipher_v2.py` y `grover_layer.py`) ya esta probado y funcional. `servidor.py`, `cliente.py` y `bot.py` siguen el protocolo tal como fue diseñado, pero aun no se han vuelto a probar contra una instancia real de Telegram ni un despliegue de red real.

Si encuentras algo que corregir o quieres proponer una mejora, abre un Issue o un Pull Request. Cualquiera de las autoras puede revisar y aprobar los cambios.

</details>
