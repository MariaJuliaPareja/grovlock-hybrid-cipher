"""
Módulo de gestión de sesiones (session_manager.py)

Administra toda la información relacionada con las sesiones activas:
generación de sesiones, almacenamiento temporal de solicitudes de
conexión, asociación entre usuarios conectados y gestión de las claves
derivadas obtenidas durante el proceso ECDH (Sección III.A.2 del paper).

NOTA DE RECONSTRUCCIÓN:
`EstadoSesion` está transcrita literalmente de la Fig. 10 del paper.
`SessionManager` (con su método `completar_handshake()`, mencionado en el
texto de la Sección III.B.4) no aparece como figura de código; su
implementación aquí sigue la descripción narrativa del flujo completo
(Sección II.C.2): registrar solicitudes pendientes, aceptar solicitudes,
y ejecutar el handshake ECDH entre las dos sesiones involucradas.
"""

from __future__ import annotations

from typing import Dict, Optional

from hybrid_cipher_v2 import SesionCifradoV2


class EstadoSesion:
    """Estado de la sesión entre dos usuarios."""
    ESPERANDO_HANDSHAKE = "esperando_handshake"
    ACTIVA = "activa"

    def __init__(self, owner_id: int):
        self.owner_id = owner_id
        self.sesion = SesionCifradoV2(str(owner_id))
        self.estado = self.ESPERANDO_HANDSHAKE
        self.partner_id: Optional[int] = None

    @property
    def lista(self) -> bool:
        return self.estado == self.ACTIVA


class SessionManager:
    """
    Mantiene en memoria el estado de todas las sesiones activas: pares de
    claves, solicitudes pendientes de conexión, claves de sesión derivadas
    y contadores de mensaje (Sección III.A.2).
    """

    def __init__(self):
        self.sesiones: Dict[int, EstadoSesion] = {}
        self.solicitudes_pendientes: Dict[int, int] = {}  # destino_id -> origen_id

    def nueva_sesion(self, owner_id: int) -> EstadoSesion:
        estado = EstadoSesion(owner_id)
        self.sesiones[owner_id] = estado
        return estado

    def solicitar_conexion(self, origen_id: int, destino_id: int) -> None:
        """Corresponde a /conectar <id_destino> (Sección III.B.3)."""
        self.solicitudes_pendientes[destino_id] = origen_id

    def completar_handshake(self, aceptante_id: int, origen_id: int) -> bytes:
        """
        Ejecuta el protocolo ECDH entre dos sesiones: ambas intercambian
        únicamente sus claves públicas y calculan localmente el mismo
        secreto compartido (Sección III.B.4).
        """
        sesion_aceptante = self.sesiones[aceptante_id]
        sesion_origen = self.sesiones[origen_id]

        clave_aceptante = sesion_aceptante.sesion.completar_handshake(
            sesion_origen.sesion.clave_publica_propia_b64
        )
        sesion_origen.sesion.completar_handshake(
            sesion_aceptante.sesion.clave_publica_propia_b64
        )

        sesion_aceptante.estado = EstadoSesion.ACTIVA
        sesion_origen.estado = EstadoSesion.ACTIVA
        sesion_aceptante.partner_id = origen_id
        sesion_origen.partner_id = aceptante_id

        self.solicitudes_pendientes.pop(aceptante_id, None)
        return clave_aceptante
