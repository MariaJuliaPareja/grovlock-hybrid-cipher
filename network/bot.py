"""
Módulo de comunicación (bot.py)

Punto de interacción entre los usuarios y el sistema: registra los
comandos disponibles, recibe solicitudes, coordina el intercambio de
mensajes y se comunica con la API oficial de Telegram (Sección III.A.1).

NOTA DE RECONSTRUCCIÓN:
`main()` está transcrita literalmente de la Fig. 9 del paper (incluyendo
el orden exacto de comandos registrados). Los handlers individuales
(cmd_start, cmd_miid, cmd_nueva_sesion, cmd_conectar, cmd_aceptar,
cmd_enviar, cmd_descifrar, cmd_estado, cmd_ayuda, mensaje_libre) no
aparecen como figuras de código; se reconstruyen siguiendo el flujo de 7
pasos descrito en la Sección III.B ("Flujo Completo del Protocolo en
Telegram") y la Tabla I (comandos del bot).

Requiere: pip install python-telegram-bot cryptography
Variable de entorno TOKEN con el token del bot de Telegram.
"""

from __future__ import annotations

import os

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from session_manager import SessionManager

TOKEN = os.environ.get("TOKEN", "")

manager = SessionManager()


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Hola! Este bot cifra tus mensajes con un algoritmo propio que combina:\n\n"
        "🔑 ECDH X25519 — intercambio de claves asimétrico\n"
        "⚛️ Difusor de Grover — capa cuántica simulada\n"
        "🔒 AES-256-GCM — cifrado simétrico autenticado\n\n"
        "Telegram nunca ve tus mensajes en claro.\n\n"
        "Para empezar:\n"
        "📇 /miid — anota tu ID y compártelo con tu contacto\n"
        "🆕 /nuevasesion — genera tus claves\n"
        "🔗 /conectar <id_del_otro> — inicia el handshake\n"
        "El otro ejecuta /aceptar <tu_id>\n"
        "✉️ /enviar <mensaje> — ¡listo!\n\n"
        "/ayuda para ver todos los comandos."
    )


async def cmd_miid(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Muestra el Telegram User ID (Sección III.B.1)."""
    user_id = update.effective_user.id
    await update.message.reply_text(
        f"Tu Telegram User ID\n\n{user_id}\n\n"
        "Comparte este número con quien quieras contactarte. Lo necesita "
        "para ejecutar /conectar."
    )


async def cmd_nueva_sesion(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Crea internamente un objeto SesionCifradoV2, genera el par de claves
    X25519. La clave privada nunca sale del servidor (Sección III.B.2).
    """
    user_id = update.effective_user.id
    estado = manager.nueva_sesion(user_id)
    await update.message.reply_text(
        "Nueva sesión iniciada\n\n"
        "Se generó un par de claves X25519 (Curve25519) para ti.\n\n"
        f"Tu clave pública:\n{estado.sesion.clave_publica_propia_b64}\n\n"
        f"Tu ID: {user_id}\n\n"
        "Ahora:\n"
        "- Si tú inicias: usa /conectar <id_del_otro>\n"
        "- Si el otro ya inició: dile que use /conectar " + str(user_id)
    )


async def cmd_conectar(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/conectar <id_destino> — Sección III.B.3."""
    user_id = update.effective_user.id
    if not context.args:
        await update.message.reply_text("Uso: /conectar <id_destino>")
        return
    destino_id = int(context.args[0])
    manager.solicitar_conexion(origen_id=user_id, destino_id=destino_id)
    await update.message.reply_text(f"Solicitud de conexión enviada a {destino_id}.")
    try:
        await context.bot.send_message(
            chat_id=destino_id,
            text=(
                f"Nueva solicitud de conexión cifrada de {user_id}.\n"
                f"Si aún no tienes sesión, primero ejecuta /nuevasesion.\n"
                f"Luego acepta con: /aceptar {user_id}"
            ),
        )
    except Exception:
        await update.message.reply_text(
            "No se pudo notificar automáticamente al otro usuario "
            "(puede que no haya iniciado el bot todavía)."
        )


async def cmd_aceptar(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/aceptar <id_origen> — ejecuta el ECDH (Sección III.B.4)."""
    user_id = update.effective_user.id
    if not context.args:
        await update.message.reply_text("Uso: /aceptar <id_origen>")
        return
    origen_id = int(context.args[0])

    if user_id not in manager.sesiones:
        manager.nueva_sesion(user_id)

    clave = manager.completar_handshake(aceptante_id=user_id, origen_id=origen_id)

    await update.message.reply_text(
        "Sesión cifrada establecida\n\n"
        f"Algoritmo: HybridECDH-Grover-AES v2\n"
        f"Clave derivada: {clave.hex()[:12]}...\n"
        "Capa Grover: activa (rondas derivadas de la clave)\n\n"
        "Ahora usa /enviar <mensaje> para cifrar y enviar."
    )
    try:
        await context.bot.send_message(
            chat_id=origen_id,
            text=f"El usuario {user_id} aceptó tu conexión. Sesión cifrada establecida.",
        )
    except Exception:
        pass


async def cmd_enviar(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/enviar <mensaje> — cifra con Grover+AES y entrega al destinatario."""
    user_id = update.effective_user.id
    if not context.args:
        await update.message.reply_text("Uso: /enviar <mensaje>")
        return

    estado = manager.sesiones.get(user_id)
    if estado is None or not estado.lista:
        await update.message.reply_text("No tienes una sesión activa. Usa /nuevasesion primero.")
        return

    mensaje = " ".join(context.args)
    cifrado_b64 = estado.sesion.cifrar_mensaje(mensaje)

    await update.message.reply_text(
        f"Mensaje cifrado y enviado\n\nTexto plano: {mensaje}\n\n"
        f"Cifrado (lo que viaja por Telegram):\n{cifrado_b64}\n\n"
        f"→ Enviado a {estado.partner_id}"
    )

    destinatario_estado = manager.sesiones.get(estado.partner_id)
    if destinatario_estado is not None:
        texto_plano = destinatario_estado.sesion.descifrar_mensaje(cifrado_b64)
        await context.bot.send_message(
            chat_id=estado.partner_id,
            text=(
                f"Mensaje cifrado recibido\n\n"
                f"Cifrado (lo que viajó por Telegram):\n{cifrado_b64}\n\n"
                f"✅ Descifrado automáticamente:\n{texto_plano}\n\n"
                f"De: {user_id}"
            ),
        )


async def cmd_descifrar(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/descifrar <base64> — descifra manualmente un texto recibido."""
    user_id = update.effective_user.id
    if not context.args:
        await update.message.reply_text("Uso: /descifrar <base64>")
        return

    estado = manager.sesiones.get(user_id)
    if estado is None or not estado.lista:
        await update.message.reply_text("No tienes una sesión activa.")
        return

    b64_texto = context.args[0]
    try:
        texto_plano = estado.sesion.descifrar_mensaje(b64_texto)
        await update.message.reply_text(f"Descifrado:\n{texto_plano}")
    except Exception as e:
        await update.message.reply_text(f"No se pudo descifrar: {e}")


async def cmd_estado(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Muestra estado de sesión: pareja, clave derivada, mensajes enviados."""
    user_id = update.effective_user.id
    estado = manager.sesiones.get(user_id)
    if estado is None:
        await update.message.reply_text("No has iniciado ninguna sesión. Usa /nuevasesion.")
        return

    clave_hex = estado.sesion.clave_sesion.hex()[:12] + "..." if estado.sesion.clave_sesion else "—"
    await update.message.reply_text(
        f"Estado de sesión\n\n"
        f"Estado: {estado.estado}\n"
        f"Pareja: {estado.partner_id or '—'}\n"
        f"Clave derivada: {clave_hex}\n"
        f"Mensajes enviados: {estado.sesion.contador_mensajes}"
    )


async def cmd_ayuda(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Comandos disponibles (Tabla I del paper):\n\n"
        "/start — Bienvenida e instrucciones\n"
        "/miid — Muestra tu Telegram User ID\n"
        "/nuevasesion — Genera par de claves X25519 e inicia handshake\n"
        "/conectar <id> — Solicita conexión cifrada con otro usuario\n"
        "/aceptar <id> — Acepta la solicitud y completa el handshake ECDH\n"
        "/enviar <mensaje> — Cifra con Grover+AES y entrega al destinatario\n"
        "/descifrar <base64> — Descifra manualmente un texto recibido\n"
        "/estado — Muestra estado de sesión"
    )


async def mensaje_libre(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Para enviar un mensaje cifrado usa /enviar <mensaje>. "
        "Escribe /ayuda para ver todos los comandos."
    )


def main():
    print("=" * 60)
    print("  HybridECDH-Grover-AES Bot  —  Iniciando...")
    print("=" * 60)

    app = Application.builder().token(TOKEN).build()

    # Registrar handlers
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("miid", cmd_miid))
    app.add_handler(CommandHandler("nuevasesion", cmd_nueva_sesion))
    app.add_handler(CommandHandler("conectar", cmd_conectar))
    app.add_handler(CommandHandler("aceptar", cmd_aceptar))
    app.add_handler(CommandHandler("enviar", cmd_enviar))
    app.add_handler(CommandHandler("descifrar", cmd_descifrar))
    app.add_handler(CommandHandler("estado", cmd_estado))
    app.add_handler(CommandHandler("ayuda", cmd_ayuda))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, mensaje_libre))

    print("  Bot corriendo. Presiona Ctrl+C para detener.")
    print("=" * 60)
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
