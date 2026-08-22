#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verificar.py - Verificador independiente de paquetes wastra-export/1.0

    python3 verificar.py <paquete.zip> [opciones]

Comprueba que un paquete exportado por la plataforma WASTRA no ha sido
alterado. Lo hace **sin credenciales, sin conexion y sin la cooperacion de
nadie**, ni siquiera de WASTRA.

Lo que este programa acredita:  integridad, orden, autoria y anterioridad.
Lo que NO acredita:             que lo declarado sea verdad.

Capas, en este orden y con veredicto propio cada una:

    C1  Estructura   el paquete esta bien formado y dice de si mismo la verdad
    C2  Cadena       cada evento conserva su huella y su enlace con el anterior
    C3  Merkle       cada evento reconstruye la raiz declarada de su dia
    C4  Anclaje      (opcional, --con-anclaje) la raiz estaba en Bitcoin

La progresion importa y es el argumento del sistema: quien tenga acceso total
a la base de datos puede recalcular toda la cadena y superar C2; puede incluso
recalcular las raices y superar C3; pero no puede reescribir lo que la cadena
publica ya presencio, y ahi falla C4.

Requisitos: Python 3.9 o superior. **Ninguna dependencia externa.**
El nucleo (C1-C3) no accede a la red en ningun caso.

(c) 2026 Angel Jose Jimenez Alvarez (marca Bimeth). Licencia Apache-2.0.
"""
from __future__ import annotations

import argparse
import binascii
import hashlib
import io
import json
import os
import re
import sys
import zipfile

VERSION = "1.1.0"
FORMATO = "wastra-export"
VERSION_FORMATO = "1.0"

# El aviso lo lleva el verificador compilado en su codigo. Nunca se imprime el
# del paquete: el informe es la voz del verificador, no un canal para que un
# paquete hostil escriba lo que quiera (§7.2 de la especificacion).
AVISO_CANONICO = (
    "Este paquete acredita integridad, orden, autoría y anterioridad de las "
    "declaraciones registradas. No acredita la veracidad de su contenido."
)

CEROS64 = "0" * 64
RE_HEX64 = re.compile(r"^[0-9a-f]{64}$")
RE_UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
RE_TS = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z$")
RE_DIA = re.compile(r"^\d{4}-\d{2}-\d{2}$")

CLAVES_EVENTO = frozenset([
    "id", "secuencia", "tipo", "autor_id", "dispositivo_id",
    "ts_dispositivo", "ts_servidor", "payload", "hash_anterior", "hash",
])

RUTA_MANIFIESTO = "manifiesto.json"
RUTA_ESPEC = "ESPECIFICACION-FORMATO.md"
RUTA_EVENTOS = "eventos/eventos.jsonl"

# Limites de seguridad al abrir el ZIP (§14). Un paquete no deberia acercarse
# ni de lejos a estos valores; existen para que un fichero hostil no agote la
# memoria del auditor.
MAX_BYTES_TOTAL = 2 * 1024 * 1024 * 1024      # 2 GiB descomprimidos
MAX_BYTES_ENTRADA = 512 * 1024 * 1024         # 512 MiB por entrada
MAX_RATIO = 1000                              # relacion de compresion admisible
MAX_ENTRADAS = 100000

SALIDA_OK = 0
SALIDA_FALLO = 1
SALIDA_MALFORMADO = 2
SALIDA_ERROR = 3


# =============================================================================
# Errores del propio paquete
# =============================================================================

class PaqueteInvalido(Exception):
    """El paquete no se puede ni abrir: no hay nada que verificar."""


# =============================================================================
# Canonicalizacion y huellas (§4, §5)
# =============================================================================

class _ProhibidoFlotante(ValueError):
    pass


def _rechaza_float(_texto):
    raise _ProhibidoFlotante(
        "número en coma flotante o notación exponencial; la especificación "
        "solo admite enteros en la unidad mínima"
    )


def _rechaza_constante(nombre):
    raise _ProhibidoFlotante("valor no permitido: %s" % nombre)


def _pares_sin_duplicados(pares):
    """object_pairs_hook que rechaza claves repetidas a cualquier profundidad.

    No se aplica ninguna regla de «gana la última»: se rechaza (§4.6).
    """
    visto = {}
    for clave, valor in pares:
        if clave in visto:
            raise ValueError("clave duplicada en un objeto JSON: %r" % clave)
        visto[clave] = valor
    return visto


def cargar_json(texto, donde):
    """Carga JSON aplicando las prohibiciones de §4: sin flotantes, sin claves
    duplicadas, sin NaN ni Infinity."""
    try:
        return json.loads(
            texto,
            object_pairs_hook=_pares_sin_duplicados,
            parse_float=_rechaza_float,
            parse_constant=_rechaza_constante,
        )
    except _ProhibidoFlotante as e:
        raise ValueError("%s: %s" % (donde, e))
    except ValueError as e:
        raise ValueError("%s: JSON inválido (%s)" % (donde, e))


def canonico(obj):
    """Serializacion canonica wastra-json-canonico/1.0 (§4)."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(datos):
    return hashlib.sha256(datos).hexdigest()


def bytes_de_hex(h):
    return binascii.unhexlify(h)


def hash_evento(evento):
    """hex(SHA256(canónico(evento sin la clave 'hash'))) — §8.5."""
    sin_hash = dict(evento)
    sin_hash.pop("hash", None)
    return sha256_hex(canonico(sin_hash))


def contiene_flotante(obj):
    """Segunda red: un float que hubiera llegado por otra vía que el parser."""
    if isinstance(obj, float):
        return True
    if isinstance(obj, dict):
        return any(contiene_flotante(v) for v in obj.values())
    if isinstance(obj, list):
        return any(contiene_flotante(v) for v in obj)
    return False


# =============================================================================
# Merkle RFC 6962 (§10)
# =============================================================================

def _k_menor(n):
    """Mayor potencia de 2 estrictamente menor que n."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(hojas):
    """Merkle Tree Hash de RFC 6962 sobre hojas de 32 bytes.

    Con separación de dominio (0x00 hoja, 0x01 nodo interno) y **sin duplicar**
    el último nodo impar. Las dos cosas son deliberadas: la primera evita el
    ataque de segunda preimagen; la segunda evita la ambigüedad conocida del
    esquema de Bitcoin, en el que [a,b,c] y [a,b,c,c] producen la misma raíz.
    """
    n = len(hojas)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hashlib.sha256(b"\x00" + hojas[0]).digest()
    k = _k_menor(n)
    return hashlib.sha256(b"\x01" + mth(hojas[:k]) + mth(hojas[k:])).digest()


def raiz_desde_prueba(hash_hoja_hex, indice, num_hojas, ruta_hex):
    """Reconstruye la raíz desde una hoja y su camino de auditoría (§10.4).

    La ruta es solo la lista ordenada de hermanas: el lado se **deriva** del
    índice y del total de hojas, nunca se lee del fichero. Dos fuentes de
    verdad podrían discrepar, y aquí no puede haber ambigüedad.

    Devuelve (raiz_hex, None) si el camino es coherente, o (None, motivo).
    """
    if num_hojas <= 0:
        return None, "num_hojas debe ser mayor que cero"
    if not (0 <= indice < num_hojas):
        return None, "índice %d fuera del árbol (num_hojas=%d)" % (indice, num_hojas)

    fn = indice
    sn = num_hojas - 1
    r = hashlib.sha256(b"\x00" + bytes_de_hex(hash_hoja_hex)).digest()

    for paso, hermana_hex in enumerate(ruta_hex):
        s = bytes_de_hex(hermana_hex)
        if sn == 0:
            return None, "la ruta tiene más pasos (%d) de los que el árbol admite" % len(ruta_hex)
        if (fn & 1) or (fn == sn):
            r = hashlib.sha256(b"\x01" + s + r).digest()
            if not (fn & 1):
                while True:
                    fn >>= 1
                    sn >>= 1
                    if (fn & 1) or fn == 0:
                        break
        else:
            r = hashlib.sha256(b"\x01" + r + s).digest()
        fn >>= 1
        sn >>= 1

    if sn != 0:
        return None, "la ruta es más corta de lo que el árbol exige"
    return binascii.hexlify(r).decode("ascii"), None


# =============================================================================
# Resultado de una capa
# =============================================================================

class Capa(object):
    def __init__(self, codigo, nombre):
        self.codigo = codigo
        self.nombre = nombre
        self.estado = "PENDIENTE"      # CORRECTO | FALLO | OMITIDO | PENDIENTE
        self.resumen = ""
        self.fallos = []               # lista de dicts
        self.advertencias = []         # lista de str

    def fallo(self, mensaje, **detalle):
        d = {"mensaje": mensaje}
        d.update(detalle)
        self.fallos.append(d)
        self.estado = "FALLO"

    def aviso(self, mensaje):
        self.advertencias.append(mensaje)

    def cerrar(self, resumen):
        if self.estado != "FALLO":
            self.estado = "CORRECTO"
        self.resumen = resumen

    def a_dict(self):
        return {
            "capa": self.codigo, "nombre": self.nombre, "estado": self.estado,
            "resumen": self.resumen, "fallos": self.fallos,
            "advertencias": self.advertencias,
        }


# =============================================================================
# Apertura segura del paquete (§14)
# =============================================================================

def abrir_paquete(ruta):
    """Abre el ZIP con las protecciones obligatorias. Devuelve {nombre: bytes}."""
    if not os.path.exists(ruta):
        raise PaqueteInvalido("no existe el fichero: %s" % ruta)
    if not zipfile.is_zipfile(ruta):
        raise PaqueteInvalido("no es un fichero ZIP: %s" % ruta)

    contenido = {}
    total = 0
    with zipfile.ZipFile(ruta) as z:
        entradas = z.infolist()
        if len(entradas) > MAX_ENTRADAS:
            raise PaqueteInvalido("el paquete tiene demasiadas entradas (%d)" % len(entradas))
        for info in entradas:
            nombre = info.filename
            if nombre.endswith("/"):
                continue
            # Nunca se escribe nada en disco, pero un nombre hostil tampoco se acepta.
            if nombre.startswith("/") or nombre.startswith("\\") or ".." in nombre.split("/"):
                raise PaqueteInvalido("ruta no admitida dentro del paquete: %r" % nombre)
            if (info.external_attr >> 16) & 0xA000 == 0xA000:
                raise PaqueteInvalido("el paquete contiene un enlace simbólico: %r" % nombre)
            if info.file_size > MAX_BYTES_ENTRADA:
                raise PaqueteInvalido("entrada demasiado grande: %r (%d bytes)" % (nombre, info.file_size))
            if info.compress_size > 0 and info.file_size // max(info.compress_size, 1) > MAX_RATIO:
                raise PaqueteInvalido("relación de compresión sospechosa en %r" % nombre)
            total += info.file_size
            if total > MAX_BYTES_TOTAL:
                raise PaqueteInvalido("el paquete descomprimido supera el límite admitido")
            contenido[nombre] = z.read(nombre)
    return contenido


def texto_utf8(datos, donde):
    """Decodifica UTF-8 rechazando el BOM (§3)."""
    if datos.startswith(b"\xef\xbb\xbf"):
        raise ValueError("%s: lleva BOM UTF-8; la especificación lo prohíbe "
                         "porque altera la huella sin dejar rastro visible" % donde)
    try:
        return datos.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError("%s: no es UTF-8 válido (%s)" % (donde, e))


# =============================================================================
# Comprobaciones auxiliares
# =============================================================================

def ts_valido(valor):
    """Marca ISO 8601 UTC estricta con milisegundos y sufijo Z, y fecha real."""
    m = RE_TS.match(valor or "")
    if not m:
        return False
    a, mes, dia, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    if not (1 <= mes <= 12 and 1 <= dia <= 31 and h <= 23 and mi <= 59 and s <= 60):
        return False
    import datetime
    try:
        datetime.date(a, mes, min(dia, 28) if False else dia)
    except ValueError:
        return False
    return True


def dia_de(ts_servidor):
    """El día de un evento lo fija su ts_servidor en UTC (§11)."""
    return ts_servidor[:10]


def sin_control(texto):
    return not any(ord(c) < 32 or ord(c) == 127 for c in texto)


# =============================================================================
# C1 · Estructura
# =============================================================================

def capa_c1(contenido, estricto):
    c = Capa("C1", "Estructura")
    datos = {"manifiesto": None, "eventos": [], "merkle": {}, "espec_bytes": None}

    # --- ficheros obligatorios ------------------------------------------
    for necesario in (RUTA_MANIFIESTO, RUTA_ESPEC, RUTA_EVENTOS):
        if necesario not in contenido:
            c.fallo("falta un fichero obligatorio del paquete", fichero=necesario)
    if c.estado == "FALLO":
        c.resumen = "faltan ficheros obligatorios"
        return c, datos

    esperados = set([RUTA_MANIFIESTO, RUTA_ESPEC, RUTA_EVENTOS])
    for nombre in contenido:
        if nombre in esperados:
            continue
        if nombre.startswith("merkle/") and nombre.endswith(".json"):
            continue
        if nombre.startswith("anclas/") and nombre.endswith(".ots"):
            continue
        msg = "fichero inesperado dentro del paquete: %s" % nombre
        if estricto:
            c.fallo(msg)
        else:
            c.aviso(msg)

    # --- manifiesto ------------------------------------------------------
    try:
        texto_man = texto_utf8(contenido[RUTA_MANIFIESTO], RUTA_MANIFIESTO)
        manifiesto = cargar_json(texto_man, RUTA_MANIFIESTO)
    except ValueError as e:
        c.fallo(str(e), fichero=RUTA_MANIFIESTO)
        c.resumen = "el manifiesto no se puede leer"
        return c, datos
    if not isinstance(manifiesto, dict):
        c.fallo("el manifiesto no es un objeto JSON", fichero=RUTA_MANIFIESTO)
        c.resumen = "manifiesto inválido"
        return c, datos
    datos["manifiesto"] = manifiesto

    if manifiesto.get("formato") != FORMATO:
        c.fallo("el paquete no declara el formato wastra-export",
                declarado=manifiesto.get("formato"))
    if str(manifiesto.get("version")) != VERSION_FORMATO:
        c.fallo("versión de formato no soportada por este verificador",
                declarado=manifiesto.get("version"), soportada=VERSION_FORMATO)

    if manifiesto.get("aviso") != AVISO_CANONICO:
        c.fallo("el aviso obligatorio del manifiesto no coincide, carácter a "
                "carácter, con el texto canónico de la especificación")

    for clave, valor in (("algoritmo_huella", "SHA-256"),
                         ("canonicalizacion", "wastra-json-canonico/1.0"),
                         ("merkle", "RFC6962")):
        if manifiesto.get(clave) != valor:
            c.fallo("el manifiesto declara %s=%r y este verificador solo "
                    "implementa %r" % (clave, manifiesto.get(clave), valor))

    tipos_declarados = manifiesto.get("tipos_declarados")
    if not isinstance(tipos_declarados, list) or not all(isinstance(t, str) for t in tipos_declarados):
        c.fallo("tipos_declarados ausente o mal formado en el manifiesto")
        tipos_declarados = []

    # --- comprobacion a tres bandas de la especificacion (§16) -----------
    espec_bytes = contenido[RUTA_ESPEC]
    datos["espec_bytes"] = espec_bytes
    if espec_bytes.startswith(b"\xef\xbb\xbf"):
        c.fallo("la especificación incrustada lleva BOM", fichero=RUTA_ESPEC)
    espec_hash = sha256_hex(espec_bytes)
    declarado = manifiesto.get("especificacion_sha256")
    if not isinstance(declarado, str) or not RE_HEX64.match(declarado or ""):
        c.fallo("especificacion_sha256 ausente o mal formado en el manifiesto")
    elif declarado != espec_hash:
        c.fallo("la especificación incrustada no coincide con la huella que el "
                "manifiesto declara: el paquete ya no se autodescribe",
                declarado=declarado, recalculado=espec_hash)

    # --- eventos ---------------------------------------------------------
    try:
        texto_ev = texto_utf8(contenido[RUTA_EVENTOS], RUTA_EVENTOS)
    except ValueError as e:
        c.fallo(str(e), fichero=RUTA_EVENTOS)
        c.resumen = "eventos.jsonl no se puede leer"
        return c, datos

    if texto_ev and "\r\n" in texto_ev:
        c.fallo("eventos.jsonl usa finales de línea CRLF; la especificación "
                "exige LF, porque CRLF altera las huellas")

    eventos = []
    ids_vistos = {}
    anterior_secuencia = None
    for n, linea in enumerate(texto_ev.split("\n"), 1):
        if linea.strip() == "":
            if n <= len(texto_ev.split("\n")) - 1:
                c.fallo("línea vacía en eventos.jsonl", linea=n)
            continue
        try:
            ev = cargar_json(linea, "eventos.jsonl línea %d" % n)
        except ValueError as e:
            c.fallo(str(e), linea=n)
            continue
        if not isinstance(ev, dict):
            c.fallo("la línea no contiene un objeto JSON", linea=n)
            continue

        claves = set(ev.keys())
        if claves != CLAVES_EVENTO:
            sobran = sorted(claves - CLAVES_EVENTO)
            faltan = sorted(CLAVES_EVENTO - claves)
            c.fallo("el nivel superior del evento no tiene exactamente las diez "
                    "claves del formato", linea=n, sobran=sobran, faltan=faltan)
            continue

        for campo in ("id", "tipo", "autor_id", "dispositivo_id",
                      "ts_dispositivo", "ts_servidor", "hash_anterior", "hash"):
            if ev[campo] is None:
                c.fallo("campo nulo no permitido en el nivel superior",
                        linea=n, campo=campo)
        if ev["secuencia"] is None:
            c.fallo("secuencia nula", linea=n)

        if not isinstance(ev["id"], str) or not RE_UUID4.match(ev["id"] or ""):
            c.fallo("id que no es un UUID versión 4 en minúsculas",
                    linea=n, id=ev.get("id"))
        elif ev["id"] in ids_vistos:
            c.fallo("id de evento duplicado en el paquete", linea=n,
                    id=ev["id"], primera_linea=ids_vistos[ev["id"]])
        else:
            ids_vistos[ev["id"]] = n

        if not isinstance(ev["secuencia"], int) or isinstance(ev["secuencia"], bool):
            c.fallo("secuencia que no es un entero", linea=n, valor=ev["secuencia"])
        elif ev["secuencia"] < 1:
            c.fallo("secuencia menor que 1", linea=n, valor=ev["secuencia"])
        else:
            if anterior_secuencia is not None and ev["secuencia"] <= anterior_secuencia:
                c.fallo("eventos.jsonl no está en orden de secuencia "
                        "estrictamente creciente", linea=n,
                        anterior=anterior_secuencia, actual=ev["secuencia"])
            anterior_secuencia = ev["secuencia"]

        for campo in ("autor_id", "dispositivo_id"):
            v = ev[campo]
            if not isinstance(v, str) or v == "":
                c.fallo("%s vacío o ausente: sin autor no hay evento" % campo, linea=n)
            elif len(v) > 128 or not sin_control(v):
                c.fallo("%s demasiado largo o con caracteres de control" % campo, linea=n)

        if not isinstance(ev["tipo"], str) or ev["tipo"] == "":
            c.fallo("tipo vacío o que no es una cadena", linea=n)
        elif tipos_declarados and ev["tipo"] not in tipos_declarados:
            c.fallo("el evento usa un tipo que el manifiesto no declara",
                    linea=n, tipo=ev["tipo"])

        for campo in ("ts_dispositivo", "ts_servidor"):
            if not isinstance(ev[campo], str) or not ts_valido(ev[campo]):
                c.fallo("%s no es una marca ISO 8601 UTC con milisegundos y "
                        "sufijo Z" % campo, linea=n, valor=ev.get(campo))

        for campo in ("hash", "hash_anterior"):
            if not isinstance(ev[campo], str) or not RE_HEX64.match(ev[campo] or ""):
                c.fallo("%s no es hexadecimal minúsculo de 64 caracteres" % campo,
                        linea=n, valor=ev.get(campo))

        if not isinstance(ev["payload"], dict):
            c.fallo("payload que no es un objeto", linea=n)
        elif contiene_flotante(ev["payload"]):
            c.fallo("payload con un número en coma flotante", linea=n)

        eventos.append({"n": n, "ev": ev})

    datos["eventos"] = eventos
    if not eventos:
        c.fallo("el paquete no contiene ningún evento")
        c.resumen = "sin eventos"
        return c, datos

    # --- CORRECCION (§8.7) ----------------------------------------------
    por_id = {}
    for i, reg in enumerate(eventos):
        por_id[reg["ev"]["id"]] = i
    arranca_en_uno = eventos[0]["ev"].get("secuencia") == 1
    for i, reg in enumerate(eventos):
        ev = reg["ev"]
        if ev.get("tipo") != "CORRECCION":
            continue
        payload = ev.get("payload") if isinstance(ev.get("payload"), dict) else {}
        referencia = payload.get("corrige_evento_id")
        if not isinstance(referencia, str) or referencia == "":
            c.fallo("evento CORRECCION sin corrige_evento_id en su payload",
                    linea=reg["n"], id=ev.get("id"))
            continue
        if referencia in por_id:
            if por_id[referencia] >= i:
                c.fallo("un evento CORRECCION referencia un evento que no es "
                        "anterior a él", linea=reg["n"], referencia=referencia)
        elif arranca_en_uno:
            c.fallo("un evento CORRECCION referencia un evento inexistente, y "
                    "el paquete contiene la historia completa desde el "
                    "principio", linea=reg["n"], referencia=referencia)
        else:
            msg = ("el evento CORRECCION de la línea %d referencia %s, anterior "
                   "al inicio de este paquete: no es verificable aquí"
                   % (reg["n"], referencia))
            if estricto:
                c.fallo(msg)
            else:
                c.aviso(msg)

    # --- manifiesto contrastado con el contenido (§7.1) ------------------
    if manifiesto.get("num_eventos") != len(eventos):
        c.fallo("el manifiesto declara un número de eventos distinto del real",
                declarado=manifiesto.get("num_eventos"), contados=len(eventos))

    dias_reales = sorted({dia_de(r["ev"]["ts_servidor"]) for r in eventos
                          if isinstance(r["ev"].get("ts_servidor"), str)})
    dias_declarados = manifiesto.get("dias")
    if not isinstance(dias_declarados, list) or dias_declarados != dias_reales:
        c.fallo("la lista de días del manifiesto no coincide con los días de "
                "los eventos", declarados=dias_declarados, reales=dias_reales)

    rango = manifiesto.get("rango")
    if not isinstance(rango, dict) or rango.get("desde") != (dias_reales[0] if dias_reales else None) \
            or rango.get("hasta") != (dias_reales[-1] if dias_reales else None):
        c.fallo("el rango declarado no coincide con las fechas de los eventos",
                declarado=rango, real={"desde": dias_reales[0] if dias_reales else None,
                                       "hasta": dias_reales[-1] if dias_reales else None})

    # --- ficheros merkle -------------------------------------------------
    dias_merkle = sorted(n[len("merkle/"):-len(".json")] for n in contenido
                         if n.startswith("merkle/") and n.endswith(".json"))
    if dias_merkle != dias_reales:
        c.fallo("los ficheros de merkle/ no corresponden exactamente a los días "
                "con eventos", en_merkle=dias_merkle, con_eventos=dias_reales)

    eventos_por_dia = {}
    for reg in eventos:
        ts = reg["ev"].get("ts_servidor")
        if isinstance(ts, str) and RE_TS.match(ts):
            eventos_por_dia.setdefault(dia_de(ts), []).append(reg["ev"])

    for dia in dias_merkle:
        nombre = "merkle/%s.json" % dia
        if not RE_DIA.match(dia):
            c.fallo("nombre de fichero merkle con fecha mal formada", fichero=nombre)
            continue
        try:
            m = cargar_json(texto_utf8(contenido[nombre], nombre), nombre)
        except ValueError as e:
            c.fallo(str(e), fichero=nombre)
            continue
        if not isinstance(m, dict):
            c.fallo("el fichero merkle no es un objeto JSON", fichero=nombre)
            continue
        datos["merkle"][dia] = m

        if m.get("fecha") != dia:
            c.fallo("el fichero merkle declara una fecha distinta de la de su "
                    "nombre", fichero=nombre, declarada=m.get("fecha"))
        raiz = m.get("raiz")
        if not isinstance(raiz, str) or not RE_HEX64.match(raiz or ""):
            c.fallo("raíz ausente o mal formada", fichero=nombre)

        del_dia = eventos_por_dia.get(dia, [])
        hojas_esperadas = [e["hash"] for e in del_dia]
        hojas = m.get("hojas")
        if not isinstance(hojas, list):
            c.fallo("hojas ausente; es obligatorio en la versión 1.0", fichero=nombre)
        elif hojas != hojas_esperadas:
            c.fallo("las hojas declaradas no coinciden con los eventos del día "
                    "(contenido u orden)", fichero=nombre,
                    declaradas=len(hojas), esperadas=len(hojas_esperadas))
        if m.get("num_hojas") != len(hojas_esperadas):
            c.fallo("num_hojas no coincide con el número de eventos del día",
                    fichero=nombre, declarado=m.get("num_hojas"),
                    real=len(hojas_esperadas))

        pruebas = m.get("pruebas")
        if not isinstance(pruebas, dict):
            c.fallo("pruebas ausente o mal formado", fichero=nombre)
        else:
            ids_dia = {e["id"] for e in del_dia}
            sobran = sorted(set(pruebas.keys()) - ids_dia)
            faltan = sorted(ids_dia - set(pruebas.keys()))
            if sobran:
                c.fallo("hay pruebas de inclusión de eventos que no están en el "
                        "paquete", fichero=nombre, ids=sobran[:5])
            if faltan:
                c.fallo("faltan pruebas de inclusión para eventos del día",
                        fichero=nombre, ids=faltan[:5])

    c.cerrar("%d eventos, %d día%s" % (len(eventos), len(dias_reales),
                                       "" if len(dias_reales) == 1 else "s"))
    return c, datos


# =============================================================================
# C2 · Cadena de huellas
# =============================================================================

def capa_c2(datos):
    c = Capa("C2", "Cadena de huellas")
    eventos = datos["eventos"]
    manifiesto = datos["manifiesto"] or {}
    if not eventos:
        c.fallo("no hay eventos que encadenar")
        c.resumen = "sin eventos"
        return c

    verificados = 0
    anterior = None
    for reg in eventos:
        ev = reg["ev"]
        recalculado = hash_evento(ev)
        if recalculado != ev.get("hash"):
            c.fallo("el contenido de este evento fue modificado después de su "
                    "registro",
                    linea=reg["n"], secuencia=ev.get("secuencia"),
                    id=ev.get("id"), tipo=ev.get("tipo"), autor=ev.get("autor_id"),
                    declarada=ev.get("hash"), recalculada=recalculado)
        else:
            verificados += 1

        if anterior is None:
            esperado = manifiesto.get("cadena", {}).get("hash_anterior_esperado") \
                if isinstance(manifiesto.get("cadena"), dict) else None
            if ev.get("secuencia") == 1:
                if ev.get("hash_anterior") != CEROS64:
                    c.fallo("el primer evento de la historia debe llevar 64 ceros "
                            "en hash_anterior", linea=reg["n"],
                            valor=ev.get("hash_anterior"))
            if esperado is not None and ev.get("hash_anterior") != esperado:
                c.fallo("el enganche con el paquete anterior no cuadra: el "
                        "hash_anterior del primer evento no es el que declara "
                        "el manifiesto", linea=reg["n"],
                        declarado=esperado, real=ev.get("hash_anterior"))
        else:
            if ev.get("hash_anterior") != anterior.get("hash"):
                c.fallo("la cadena está rota: este evento no enlaza con el "
                        "anterior", linea=reg["n"], secuencia=ev.get("secuencia"),
                        esperado=anterior.get("hash"), real=ev.get("hash_anterior"))
            sa, sb = anterior.get("secuencia"), ev.get("secuencia")
            if isinstance(sa, int) and isinstance(sb, int) and sb != sa + 1:
                c.fallo("hueco en la secuencia: falta al menos un evento",
                        linea=reg["n"], despues_de=sa, encontrado=sb,
                        faltan=max(0, sb - sa - 1))
        anterior = ev

    bloque = manifiesto.get("cadena")
    if isinstance(bloque, dict):
        primero, ultimo = eventos[0]["ev"], eventos[-1]["ev"]
        if bloque.get("secuencia_desde") != primero.get("secuencia"):
            c.fallo("secuencia_desde del manifiesto no coincide con el primer evento",
                    declarado=bloque.get("secuencia_desde"), real=primero.get("secuencia"))
        if bloque.get("secuencia_hasta") != ultimo.get("secuencia"):
            c.fallo("secuencia_hasta del manifiesto no coincide con el último evento",
                    declarado=bloque.get("secuencia_hasta"), real=ultimo.get("secuencia"))
        if bloque.get("hash_ultimo") != ultimo.get("hash"):
            c.fallo("hash_ultimo del manifiesto no coincide con el último evento",
                    declarado=bloque.get("hash_ultimo"), real=ultimo.get("hash"))
    else:
        c.fallo("el manifiesto no lleva el bloque cadena")

    c.cerrar("%d/%d verificados" % (verificados, len(eventos)))
    return c


# =============================================================================
# C3 · Árbol de Merkle
# =============================================================================

def capa_c3(datos):
    c = Capa("C3", "Árbol de Merkle")
    eventos = datos["eventos"]
    merkles = datos["merkle"]
    if not merkles:
        c.fallo("no hay ficheros merkle que verificar")
        c.resumen = "sin árboles"
        return c

    por_dia = {}
    for reg in eventos:
        ts = reg["ev"].get("ts_servidor")
        if isinstance(ts, str) and RE_TS.match(ts):
            por_dia.setdefault(dia_de(ts), []).append(reg["ev"])

    total = 0
    reconstruidos = 0
    for dia in sorted(merkles):
        m = merkles[dia]
        raiz_declarada = m.get("raiz")
        del_dia = por_dia.get(dia, [])

        # 1. La raíz se recalcula desde cero con los eventos del propio paquete.
        try:
            hojas = [bytes_de_hex(e["hash"]) for e in del_dia]
            raiz_recalculada = binascii.hexlify(mth(hojas)).decode("ascii")
        except (binascii.Error, TypeError, KeyError):
            c.fallo("no se pueden decodificar las huellas del día", dia=dia)
            continue
        if raiz_recalculada != raiz_declarada:
            c.fallo("la raíz declarada del día no es la que producen sus propios "
                    "eventos", dia=dia, declarada=raiz_declarada,
                    recalculada=raiz_recalculada)

        # 2. Y además cada evento debe reconstruirla por su propia ruta.
        pruebas = m.get("pruebas") if isinstance(m.get("pruebas"), dict) else {}
        for ev in del_dia:
            total += 1
            p = pruebas.get(ev["id"])
            if not isinstance(p, dict):
                c.fallo("evento sin prueba de inclusión", dia=dia, id=ev["id"])
                continue
            indice, ruta = p.get("indice"), p.get("ruta")
            if not isinstance(indice, int) or isinstance(indice, bool):
                c.fallo("índice de la prueba ausente o no entero", dia=dia, id=ev["id"])
                continue
            if not isinstance(ruta, list) or not all(
                    isinstance(x, str) and RE_HEX64.match(x) for x in ruta):
                c.fallo("ruta de la prueba ausente o mal formada", dia=dia, id=ev["id"])
                continue
            num_hojas = m.get("num_hojas")
            if not isinstance(num_hojas, int):
                c.fallo("num_hojas ausente o no entero", dia=dia)
                continue
            raiz, motivo = raiz_desde_prueba(ev["hash"], indice, num_hojas, ruta)
            if motivo:
                c.fallo("la prueba de inclusión no es coherente: %s" % motivo,
                        dia=dia, id=ev["id"], secuencia=ev.get("secuencia"))
            elif raiz != raiz_declarada:
                c.fallo("el evento no reconstruye la raíz declarada de su día",
                        dia=dia, id=ev["id"], secuencia=ev.get("secuencia"),
                        raiz_declarada=raiz_declarada, raiz_reconstruida=raiz)
            else:
                reconstruidos += 1

    c.cerrar("raíz reconstruida para %d/%d" % (reconstruidos, total))
    return c


# =============================================================================
# C4 · Anclaje (opcional, en su propio módulo)
# =============================================================================

def capa_c4(contenido, datos, opciones):
    c = Capa("C4", "Anclaje")
    if not opciones.con_anclaje:
        c.estado = "OMITIDO"
        c.resumen = "(ejecute con --con-anclaje)"
        return c
    try:
        import anclaje                                        # noqa: F401
    except ImportError:
        c.estado = "OMITIDO"
        c.resumen = "módulo de anclaje no disponible"
        c.aviso("La capa C4 necesita el módulo opcional `anclaje.py` y la "
                "biblioteca `opentimestamps`. El núcleo C1–C3 no los necesita "
                "y no accede a la red.")
        return c
    return anclaje.verificar(contenido, datos, opciones, Capa)


# =============================================================================
# Informe
# =============================================================================

def _punteado(texto, ancho=24):
    return texto + " " + "." * max(1, ancho - len(texto) - 1)


def informe_texto(nombre_paquete, capas, datos, opciones):
    L = []
    L.append("VERIFICADOR WASTRA v%s · herramienta independiente" % VERSION)
    L.append("Paquete: %s" % nombre_paquete)
    L.append("")
    for c in capas:
        L.append("  [%s] %s %-9s %s" % (c.codigo, _punteado(c.nombre), c.estado, c.resumen))
    L.append("")

    hubo_fallo = any(c.estado == "FALLO" for c in capas)
    for c in capas:
        if c.estado != "FALLO":
            continue
        L.append("  [%s] %s · detalle" % (c.codigo, c.nombre))
        for f in c.fallos[:20]:
            L.append("       %s" % f["mensaje"])
            for k, v in f.items():
                if k == "mensaje":
                    continue
                L.append("         %-16s %s" % (k + ":", v))
            L.append("")
        if len(c.fallos) > 20:
            L.append("       (y %d fallos más; use --json para verlos todos)" % (len(c.fallos) - 20))
            L.append("")

    avisos = [(c.codigo, a) for c in capas for a in c.advertencias]
    if avisos:
        L.append("  ADVERTENCIAS")
        for codigo, a in avisos:
            L.append("       [%s] %s" % (codigo, a))
        L.append("")

    if hubo_fallo:
        L.append("VEREDICTO: NO SUPERADA. El paquete no puede darse por íntegro.")
        L.append("Lo señalado arriba indica dónde y en qué consiste la discrepancia.")
    else:
        L.append("VEREDICTO: el contenido de este paquete no ha sido alterado desde su")
        L.append("exportación. La secuencia de eventos es íntegra, completa y ordenada.")
    L.append("")
    L.append("Este resultado acredita integridad, orden, autoría y anterioridad.")
    L.append("NO acredita la veracidad del contenido declarado.")

    man = datos.get("manifiesto") or {}
    if man.get("titular") or man.get("generador"):
        L.append("")
        L.append("Declarado por el paquete, NO verificado por esta herramienta:")
        if man.get("titular"):
            L.append("  titular:   %s" % man["titular"])
        if man.get("generador"):
            L.append("  generador: %s" % man["generador"])
    if not opciones.con_anclaje:
        L.append("")
        L.append("La capa C4 (anterioridad frente a una cadena pública) no se ha")
        L.append("ejecutado. Sin ella, un adversario con control total del registro")
        L.append("podría haber recalculado toda la cadena y todas las raíces.")
    return "\n".join(L)


def informe_json(nombre_paquete, capas, datos, opciones):
    man = datos.get("manifiesto") or {}
    return json.dumps({
        "verificador": {"nombre": "wastra-verificador", "version": VERSION},
        "paquete": nombre_paquete,
        "formato": {"nombre": FORMATO, "version": VERSION_FORMATO},
        "capas": [c.a_dict() for c in capas],
        "veredicto": "FALLO" if any(c.estado == "FALLO" for c in capas) else "CORRECTO",
        "declarado_no_verificado": {"titular": man.get("titular"),
                                    "generador": man.get("generador")},
        "aviso": AVISO_CANONICO,
        "c4_ejecutada": bool(opciones.con_anclaje),
    }, ensure_ascii=False, indent=2)


# =============================================================================
# Programa
# =============================================================================

def construir_argumentos():
    p = argparse.ArgumentParser(
        prog="verificar.py",
        description="Verificador independiente de paquetes wastra-export/1.0.",
        epilog="Acredita integridad, orden, autoría y anterioridad. "
               "No acredita la veracidad del contenido declarado.")
    p.add_argument("paquete", nargs="?", help="fichero .zip a verificar")
    p.add_argument("--con-anclaje", action="store_true",
                   help="verifica también la capa 4 (requiere el módulo de anclaje y red)")
    p.add_argument("--json", action="store_true", help="salida legible por máquina")
    p.add_argument("--informe", metavar="FICHERO", help="guarda el informe en un fichero")
    p.add_argument("--estricto", action="store_true",
                   help="cualquier advertencia se trata como error")
    p.add_argument("--version", action="version",
                   version="wastra-verificador %s (formato %s/%s)"
                           % (VERSION, FORMATO, VERSION_FORMATO))
    return p


def main(argv=None):
    opciones = construir_argumentos().parse_args(argv)
    if not opciones.paquete:
        construir_argumentos().print_help()
        return SALIDA_ERROR

    try:
        contenido = abrir_paquete(opciones.paquete)
    except PaqueteInvalido as e:
        print("PAQUETE MALFORMADO: %s" % e, file=sys.stderr)
        return SALIDA_MALFORMADO
    except Exception as e:                                     # noqa: BLE001
        print("ERROR DE LA HERRAMIENTA al abrir el paquete: %s" % e, file=sys.stderr)
        return SALIDA_ERROR

    try:
        c1, datos = capa_c1(contenido, opciones.estricto)
        capas = [c1]
        if c1.estado == "FALLO" and datos["manifiesto"] is None:
            texto = informe_texto(os.path.basename(opciones.paquete), capas, datos, opciones)
            print(texto)
            return SALIDA_MALFORMADO
        capas.append(capa_c2(datos))
        capas.append(capa_c3(datos))
        capas.append(capa_c4(contenido, datos, opciones))
    except Exception as e:                                     # noqa: BLE001
        print("ERROR DE LA HERRAMIENTA: %s" % e, file=sys.stderr)
        return SALIDA_ERROR

    if opciones.estricto:
        for c in capas:
            if c.advertencias and c.estado == "CORRECTO":
                c.estado = "FALLO"
                for a in c.advertencias:
                    c.fallos.append({"mensaje": "advertencia elevada a error (--estricto): %s" % a})

    nombre = os.path.basename(opciones.paquete)
    salida = (informe_json(nombre, capas, datos, opciones) if opciones.json
              else informe_texto(nombre, capas, datos, opciones))
    print(salida)
    if opciones.informe:
        with io.open(opciones.informe, "w", encoding="utf-8", newline="\n") as f:
            f.write(salida + "\n")

    return SALIDA_FALLO if any(c.estado == "FALLO" for c in capas) else SALIDA_OK


if __name__ == "__main__":
    sys.exit(main())
