# -*- coding: utf-8 -*-
"""anclaje.py - Capa C4: ¿estaba esta raíz en Bitcoin, y desde cuándo?

Módulo **opcional** de `verificar.py`. El núcleo C1–C3 no lo necesita y no
accede a la red en ningún caso; esta capa sí, y por eso vive aparte y solo se
ejecuta con `--con-anclaje`.

Qué comprueba, para cada día del paquete:

1. Que existe `anclas/AAAA-MM-DD.ots`.
2. Que esa prueba se hizo **sobre los 32 bytes binarios de la raíz de ese día**,
   no sobre su representación hexadecimal. Es el error de interoperabilidad más
   frecuente y aquí es un fallo, no una advertencia.
3. Que la prueba llega hasta una atestación de Bitcoin, y en qué bloque.
4. Qué hora tiene ese bloque — el **momento acreditado**: el instante antes del
   cual la raíz, y con ella todos los eventos de ese día, ya existía.

**Sin CLI y sin `python-bitcoinlib`** (§11.1). La cabecera del bloque son
ochenta bytes y se interpretan aquí, en veinte líneas legibles. Una promesa de
independencia no puede descansar sobre una dependencia que se rompe al cambiar
de máquina — y esa se rompía.

Tres estados, nunca aprobado/fallido (§11.2):

    SIN ANCLA    no hay prueba para ese día. No hay nada que verificar.
    PENDIENTE    enviada al calendario, aún no confirmada en Bitcoin.
                 Acredita el envío, NO todavía anterioridad independiente.
    CONFIRMADO   lleva atestación de Bitcoin. Hay momento acreditado.

De quién depende esta capa, dicho en el propio informe: por defecto consulta
**varias fuentes independientes** de cabeceras de bloque y exige que coincidan.
Ese modo **confía** en esas fuentes. Con `--nodo-bitcoin URL` se usa el nodo del
propio auditor y no se confía en nadie. Declarar de quién depende una
herramienta es lo que la separa de otra que lo oculta.

(c) 2026 Angel Jose Jimenez Alvarez (marca Bimeth). Licencia Apache-2.0.
"""
from __future__ import annotations

import binascii
import datetime
import json
import urllib.error
import urllib.request

TIEMPO_ESPERA = 20

# Fuentes independientes de cabeceras de bloque. Se exige coincidencia entre
# al menos dos: si dos operadores distintos dan la misma cabecera, mentir
# exigiria ponerse de acuerdo, y eso ya es otra cosa.
FUENTES = [
    ("blockstream.info", "https://blockstream.info/api"),
    ("mempool.space", "https://mempool.space/api"),
]


class ErrorFuente(Exception):
    pass


# =============================================================================
# Cabecera de bloque de Bitcoin — ochenta bytes, sin dependencias
# =============================================================================

def _le(b):
    """Entero sin signo desde bytes en orden little-endian."""
    return int.from_bytes(b, "little")


def interpretar_cabecera(datos):
    """Interpreta los 80 bytes de una cabecera de bloque de Bitcoin.

    version(4) || hash_previo(32) || raiz_merkle(32) || tiempo(4) || bits(4) || nonce(4)

    Todo en little-endian. La `raiz_merkle` se devuelve **en orden interno**,
    que es el que usa la atestación de OpenTimestamps. Los exploradores la
    muestran con los bytes invertidos; no es una discrepancia, es la misma
    cifra escrita al revés.
    """
    if len(datos) < 80:
        raise ErrorFuente("cabecera de bloque incompleta (%d bytes)" % len(datos))
    return {
        "version": _le(datos[0:4]),
        "hash_previo": datos[4:36],
        "raiz_merkle": datos[36:68],
        "tiempo": _le(datos[68:72]),
        "bits": _le(datos[72:76]),
        "nonce": _le(datos[76:80]),
    }


def _traer(url):
    peticion = urllib.request.Request(url, headers={"User-Agent": "wastra-verificador"})
    with urllib.request.urlopen(peticion, timeout=TIEMPO_ESPERA) as r:
        return r.read()


def cabecera_de_fuente(base, altura):
    """Devuelve (hash_bloque_hex, bytes_cabecera) desde una fuente pública."""
    try:
        bloque_hash = _traer("%s/block-height/%d" % (base, altura)).decode("ascii").strip()
        if len(bloque_hash) != 64:
            raise ErrorFuente("respuesta inesperada al pedir el hash de la altura %d" % altura)
        hexcab = _traer("%s/block/%s/header" % (base, bloque_hash)).decode("ascii").strip()
        return bloque_hash, binascii.unhexlify(hexcab)
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, binascii.Error) as e:
        raise ErrorFuente(str(e))


def cabecera_por_consenso(altura, nodo=None):
    """Cabecera del bloque, exigiendo que dos fuentes independientes coincidan.

    Devuelve (cabecera, descripcion_de_confianza, fuentes_consultadas).
    """
    if nodo:
        bloque_hash, datos = cabecera_de_fuente(nodo.rstrip("/"), altura)
        return (interpretar_cabecera(datos),
                "nodo propio del auditor (%s) — no se confía en terceros" % nodo,
                [nodo])

    obtenidas, errores = [], []
    for nombre, base in FUENTES:
        try:
            bloque_hash, datos = cabecera_de_fuente(base, altura)
            obtenidas.append((nombre, bloque_hash, datos))
        except ErrorFuente as e:
            errores.append("%s: %s" % (nombre, e))

    if not obtenidas:
        raise ErrorFuente("ninguna fuente respondió (%s)" % "; ".join(errores))
    if len(obtenidas) == 1:
        nombre, _h, datos = obtenidas[0]
        return (interpretar_cabecera(datos),
                "UNA SOLA fuente (%s) — el resto no respondió; confianza reducida" % nombre,
                [nombre])

    referencia = obtenidas[0][2]
    discrepantes = [n for n, _h, d in obtenidas if d != referencia]
    if discrepantes:
        raise ErrorFuente(
            "las fuentes consultadas NO coinciden en la cabecera del bloque %d "
            "(%s). No se acredita nada sobre una discrepancia." % (
                altura, ", ".join(n for n, _h, _d in obtenidas)))
    return (interpretar_cabecera(referencia),
            "%d fuentes independientes coincidentes (%s) — se confía en ellas" % (
                len(obtenidas), ", ".join(n for n, _h, _d in obtenidas)),
            [n for n, _h, _d in obtenidas])


# =============================================================================
# Recorrido del árbol de la prueba OpenTimestamps
# =============================================================================

def recorrer(timestamp, salida=None):
    """Devuelve [(mensaje_bytes, atestacion)] de todo el árbol de la prueba."""
    salida = [] if salida is None else salida
    for atestacion in timestamp.attestations:
        salida.append((timestamp.msg, atestacion))
    for _op, hijo in timestamp.ops.items():
        recorrer(hijo, salida)
    return salida


def leer_ots(datos):
    from opentimestamps.core.serialize import BytesDeserializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile
    ctx = BytesDeserializationContext(datos)
    return DetachedTimestampFile.deserialize(ctx)


# =============================================================================
# La capa
# =============================================================================

def verificar(contenido, datos, opciones, Capa):
    c = Capa("C4", "Anclaje")
    merkles = datos.get("merkle") or {}
    if not merkles:
        c.estado = "OMITIDO"
        c.resumen = "no hay raíces que anclar"
        return c

    try:
        from opentimestamps.core.notary import (BitcoinBlockHeaderAttestation,
                                                PendingAttestation)
    except ImportError:
        c.estado = "OMITIDO"
        c.resumen = "falta la biblioteca opentimestamps"
        c.aviso("Instale `opentimestamps` para ejecutar la capa 4. El núcleo "
                "C1–C3 no la necesita.")
        return c

    nodo = getattr(opciones, "nodo_bitcoin", None)
    estados = {}
    confianzas = set()

    for dia in sorted(merkles):
        raiz_hex = merkles[dia].get("raiz")
        nombre = "anclas/%s.ots" % dia
        if nombre not in contenido:
            estados[dia] = ("SIN ANCLA", None)
            c.aviso("%s: SIN ANCLA. Los eventos de ese día no tienen "
                    "anterioridad acreditada frente a ninguna cadena pública." % dia)
            continue

        try:
            dtf = leer_ots(contenido[nombre])
        except Exception as e:                                  # noqa: BLE001
            c.fallo("la prueba de anclaje no se puede leer", dia=dia, motivo=str(e)[:120])
            estados[dia] = ("ILEGIBLE", None)
            continue

        # 1 · La prueba debe ser sobre los 32 BYTES de la raíz, no sobre su hex.
        try:
            raiz_bytes = binascii.unhexlify(raiz_hex)
        except (binascii.Error, TypeError):
            c.fallo("la raíz declarada del día no es hexadecimal válido", dia=dia)
            continue
        if dtf.file_digest != raiz_bytes:
            if dtf.file_digest == raiz_hex.encode("ascii"):
                c.fallo("la prueba de anclaje se hizo sobre el TEXTO hexadecimal "
                        "de la raíz, no sobre sus 32 bytes. Es el error de "
                        "interoperabilidad que la especificación advierte en §11",
                        dia=dia)
            else:
                c.fallo("la prueba de anclaje no corresponde a la raíz de este "
                        "día: se ancló otra cosa", dia=dia,
                        raiz_del_dia=raiz_hex,
                        huella_anclada=binascii.hexlify(dtf.file_digest).decode("ascii"))
            estados[dia] = ("NO CORRESPONDE", None)
            continue

        # 2 · ¿Hasta dónde llega la prueba?
        atestaciones = recorrer(dtf.timestamp)
        bitcoin = [(m, a) for m, a in atestaciones
                   if isinstance(a, BitcoinBlockHeaderAttestation)]
        pendientes = [(m, a) for m, a in atestaciones
                      if isinstance(a, PendingAttestation)]

        if not bitcoin:
            if pendientes:
                estados[dia] = ("PENDIENTE", None)
                c.aviso("%s: PENDIENTE. La prueba se envió al calendario pero "
                        "todavía NO está confirmada en Bitcoin. Esto acredita el "
                        "envío al calendario, NO todavía anterioridad "
                        "independiente." % dia)
            else:
                c.fallo("la prueba no lleva atestación alguna: no acredita nada", dia=dia)
                estados[dia] = ("VACIA", None)
            continue

        # 3 · Confirmada: se comprueba contra la cabecera real del bloque.
        mensaje, atest = bitcoin[0]
        altura = atest.height
        try:
            cabecera, confianza, _fuentes = cabecera_por_consenso(altura, nodo)
        except ErrorFuente as e:
            c.fallo("no se pudo obtener la cabecera del bloque para comprobar el "
                    "anclaje", dia=dia, bloque=altura, motivo=str(e)[:150])
            estados[dia] = ("NO COMPROBABLE", None)
            continue
        confianzas.add(confianza)

        if mensaje != cabecera["raiz_merkle"]:
            c.fallo("la prueba dice terminar en la raíz de Merkle del bloque %d, "
                    "pero la cabecera real de ese bloque contiene otra" % altura,
                    dia=dia,
                    segun_la_prueba=binascii.hexlify(mensaje).decode("ascii"),
                    segun_el_bloque=binascii.hexlify(cabecera["raiz_merkle"]).decode("ascii"))
            estados[dia] = ("FALSA", None)
            continue

        momento = datetime.datetime.fromtimestamp(cabecera["tiempo"], datetime.timezone.utc)
        estados[dia] = ("CONFIRMADO", {"bloque": altura,
                                       "momento": momento.strftime("%Y-%m-%dT%H:%M:%SZ")})

    # ---- resumen -------------------------------------------------------
    cuenta = {}
    for estado, _d in estados.values():
        cuenta[estado] = cuenta.get(estado, 0) + 1
    confirmados = [(d, x) for d, (e, x) in estados.items() if e == "CONFIRMADO"]
    partes = ["%d %s" % (n, e.lower()) for e, n in sorted(cuenta.items())]
    c.resumen = ", ".join(partes)

    if confirmados:
        d, x = sorted(confirmados)[0]
        c.aviso("Momento acreditado más antiguo: %s existía ya el %s "
                "(bloque %d de Bitcoin)." % (d, x["momento"], x["bloque"]))
    for conf in sorted(confianzas):
        c.aviso("Origen de las cabeceras de bloque: %s." % conf)
    if not nodo and confirmados:
        c.aviso("Para no depender de terceros, repita con --nodo-bitcoin "
                "apuntando a su propio nodo.")

    if c.estado != "FALLO":
        c.estado = "CORRECTO" if confirmados else "OMITIDO"
        if not confirmados and not c.resumen:
            c.resumen = "sin anclaje confirmado"
    return c


def detalle_json(estados):
    return json.dumps(estados, ensure_ascii=False, indent=2)
