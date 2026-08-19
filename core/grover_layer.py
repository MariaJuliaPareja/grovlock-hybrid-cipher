"""
CAPA DE GROVER — Difusor cuántico simulado

Operador de difusión: D(v)[i] = (2μ - v[i]) mod 256
donde μ = mean(v)  —  basado en Grover (1996)

============================================================================
NOTA DE RECONSTRUCCIÓN — LEE ESTO ANTES DE USAR EN PRODUCCIÓN
============================================================================
La Fig. 5 del paper original (GrovLock: Diseño e Implementación de un
Algoritmo Híbrido de Cifrado para Comunicaciones Seguras) muestra el
código de `_difusor_grover_bloque`. Al reconstruirlo y probarlo aquí se
encontraron DOS problemas reales, no solo de transcripción:

1) BUG DE DOBLE ASIGNACIÓN (en el código de la figura):
   El bloque tiene dos líneas que asignan a `v` en el mismo round:

       v = [(doble_media_n - n * vi) % (256 * n) // n for vi in v]
       v = [(2 * S // n - vi) % 256 for vi in v]

   La segunda línea itera sobre el `v` que la primera línea YA
   reasignó, no sobre el bloque original. Como ambas aplican la misma
   reflexión D(x) = 2μ-x con la misma μ (S no se recalcula entre
   líneas), el efecto neto es D(D(x)) = x: la segunda línea deshace
   exactamente lo que hizo la primera. Tal como está en la figura, la
   función es un no-op para cualquier número de rondas.

2) PROBLEMA DE FONDO (independiente del bug anterior):
   Incluso arreglando (1) para que sí difunda, usar μ = mean(v)
   calculada de los datos del propio bloque, con división entera,
   solo es exactamente invertible cuando N divide a 2·suma (el propio
   comentario del paper lo admite). Probado empíricamente sobre 1000
   bloques aleatorios: ~95% no se revierten correctamente. Es decir,
   con datos arbitrarios el mensaje se corrompería en el descifrado la
   gran mayoría de las veces.

CORRECCIÓN APLICADA AQUÍ:
En vez de derivar la constante de reflexión de los DATOS del bloque
(lo que rompe la invertibilidad en el caso general), se deriva de la
CLAVE de sesión y la posición del bloque/ronda. Una reflexión
y = (c - x) mod 256 con c FIJO es exactamente su propia inversa sin
importar el valor de c (doble negación módulo 256: (c-(c-x)) = x,
siempre, para cualquier entero c). Esto garantiza invertibilidad
perfecta para cualquier dato, preserva la idea de "reflexión inspirada
en Grover" del paper, y de paso hace que la difusión dependa realmente
de la clave (más cerca de lo que un esquema criptográfico necesita).
============================================================================
"""

from __future__ import annotations

import hashlib
from typing import List

BLOCK_SIZE = 16  # 128 bits, según el paper


def _constante_ronda(clave: bytes, indice_bloque: int, ronda: int) -> int:
    """
    Deriva una constante de reflexión (0-255) a partir de la clave de
    sesión, el índice del bloque y el número de ronda. Determinística:
    cifrado y descifrado obtienen exactamente el mismo valor sin
    necesidad de transmitir nada adicional.
    """
    h = hashlib.sha256(
        clave + indice_bloque.to_bytes(4, "big") + ronda.to_bytes(1, "big")
    ).digest()
    return h[0]


def _difusor_grover_bloque(
    bloque: List[int], clave: bytes, indice_bloque: int, rondas: int, reverso: bool = False
) -> List[int]:
    """
    Aplica el difusor de Grover (reflexión módulo 256) a un bloque, usando
    una constante derivada de la clave en cada ronda. Cada reflexión
    individual y = (c - x) mod 256 es su propia inversa para un c fijo,
    pero encadenar varias rondas con constantes distintas NO es
    autoinverso como cadena: para deshacerla hay que aplicar las mismas
    constantes en orden INVERSO (`reverso=True`), igual que deshacer una
    pila de cajas envueltas se hace de afuera hacia adentro.
    """
    v = list(bloque)
    indices_ronda = range(rondas - 1, -1, -1) if reverso else range(rondas)
    for ronda in indices_ronda:
        c = _constante_ronda(clave, indice_bloque, ronda)
        v = [(c - vi) % 256 for vi in v]
    return v


def _rondas_desde_clave(clave: bytes) -> int:
    """
    Deriva el número de rondas de difusión a partir de la clave de sesión.

    RECONSTRUCCIÓN: el paper (Sección II.A.3) indica que "el número de
    rondas de difusión es derivado dinámicamente a partir de la clave de
    sesión generada mediante X25519 y la función KDF", sin especificar la
    fórmula exacta. Aquí se usa el primer byte de la clave, acotado a un
    rango razonable de rondas (1-8).
    """
    if not clave:
        return 3
    return (clave[0] % 8) + 1


def _pad(data: bytes) -> bytes:
    """Padding PKCS7 a múltiplos de BLOCK_SIZE. No especificado en el paper."""
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def _unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Padding inválido")
    return data[:-pad_len]


def aplicar_grover(datos: bytes, clave: bytes) -> bytes:
    """
    Aplica la capa de difusión de Grover sobre los datos completos,
    bloque por bloque de 16 bytes, antes del cifrado AES-256-GCM.
    """
    rondas = _rondas_desde_clave(clave)
    padded = _pad(datos)

    resultado = bytearray()
    for idx, i in enumerate(range(0, len(padded), BLOCK_SIZE)):
        bloque = list(padded[i:i + BLOCK_SIZE])
        transformado = _difusor_grover_bloque(bloque, clave, idx, rondas)
        resultado.extend(transformado)

    return bytes(resultado)


def revertir_grover(datos: bytes, clave: bytes) -> bytes:
    """
    Revierte la difusión de Grover. Como la reflexión con constante fija
    es su propia inversa, se reaplica exactamente el mismo procedimiento
    (misma clave, mismo índice de bloque, mismas rondas) y luego se
    quita el padding.
    """
    rondas = _rondas_desde_clave(clave)

    resultado = bytearray()
    for idx, i in enumerate(range(0, len(datos), BLOCK_SIZE)):
        bloque = list(datos[i:i + BLOCK_SIZE])
        original = _difusor_grover_bloque(bloque, clave, idx, rondas, reverso=True)
        resultado.extend(original)

    return _unpad(bytes(resultado))
