# -*- coding: utf-8 -*-
"""Diagnóstico de anclas OpenTimestamps. SOLO LECTURA: no modifica nada.

Recibe carpetas o ficheros. Empareja cada `.ots` con su fichero original
(el mismo nombre sin la extensión `.ots`) y, para cada par, informa:

  - si el SHA-256 del fichero ACTUAL coincide con el digest que la prueba
    selló. Si NO coincide, el fichero ha cambiado desde que se ancló (deriva
    de bytes, típicamente conversión CRLF<->LF) y la prueba ya no le
    corresponde.
  - si la prueba está PENDIENTE (solo atestaciones de calendario) o
    CONFIRMADA (atestación de bloque Bitcoin), o SIN ATESTACIÓN.

No accede a la red: lee los .ots y calcula huellas localmente.

Construido sobre la librería núcleo `opentimestamps`, NO sobre el CLI ni sobre
python-bitcoinlib (§11.1 de la especificación). Compatible con Python 3.9+.

Uso:
    python herramientas/comprobar_anclas.py <carpeta-o-fichero> [más rutas...]
"""
import hashlib
import os
import sys

from opentimestamps.core.timestamp import DetachedTimestampFile
from opentimestamps.core.serialize import StreamDeserializationContext
from opentimestamps.core.notary import (
    BitcoinBlockHeaderAttestation,
    LitecoinBlockHeaderAttestation,
    PendingAttestation,
    UnknownAttestation,
)


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _leer_ots(ruta_ots):
    with open(ruta_ots, "rb") as f:
        return DetachedTimestampFile.deserialize(StreamDeserializationContext(f))


def _clasifica_atestaciones(timestamp):
    pendientes, bitcoin, otras = [], [], []
    for _msg, att in timestamp.all_attestations():
        if isinstance(att, PendingAttestation):
            uri = att.uri
            if isinstance(uri, bytes):
                uri = uri.decode("utf-8", "replace")
            pendientes.append(uri)
        elif isinstance(att, BitcoinBlockHeaderAttestation):
            bitcoin.append(("bitcoin", att.height))
        elif isinstance(att, LitecoinBlockHeaderAttestation):
            bitcoin.append(("litecoin", att.height))
        else:
            otras.append(type(att).__name__)
    return pendientes, bitcoin, otras


def _diagnostico_deriva(ruta_original, digest_prueba_hex):
    """Si el digest no coincide, intenta explicar por qué comparando variantes
    de finales de línea. Devuelve un texto de diagnóstico."""
    with open(ruta_original, "rb") as f:
        crudo = f.read()
    actual = _sha256(crudo)
    if actual == digest_prueba_hex:
        return ("COINCIDE", actual, None)

    # Probar conversiones de finales de línea sobre el fichero actual.
    variantes = {
        "si se normalizara CRLF->LF": crudo.replace(b"\r\n", b"\n"),
        "si se normalizara LF->CRLF": crudo.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"),
    }
    causa = None
    for etiqueta, datos in variantes.items():
        if _sha256(datos) == digest_prueba_hex:
            causa = etiqueta
            break
    return ("NO COINCIDE", actual, causa)


def comprobar_ots(ruta_ots):
    original = ruta_ots[:-4] if ruta_ots.lower().endswith(".ots") else None
    info = {"ots": ruta_ots, "original": original}
    try:
        det = _leer_ots(ruta_ots)
    except Exception as e:
        info["error"] = "no se pudo leer la prueba: " + repr(e)
        return info

    info["algoritmo"] = type(det.file_hash_op).__name__
    info["digest_prueba"] = det.file_digest.hex()

    if not original or not os.path.exists(original):
        info["estado_fichero"] = "ORIGINAL AUSENTE"
    else:
        estado, actual, causa = _diagnostico_deriva(original, det.file_digest.hex())
        info["estado_fichero"] = estado
        info["digest_actual"] = actual
        info["causa_deriva"] = causa

    pend, btc, otras = _clasifica_atestaciones(det.timestamp)
    info["pendientes"] = pend
    info["bitcoin"] = btc
    info["otras"] = otras
    if btc:
        info["estado_ancla"] = "CONFIRMADO"
    elif pend:
        info["estado_ancla"] = "PENDIENTE"
    else:
        info["estado_ancla"] = "SIN ATESTACION"
    return info


def _buscar_ots(rutas):
    encontrados = []
    for r in rutas:
        if os.path.isdir(r):
            for base, _dirs, files in os.walk(r):
                for nombre in files:
                    if nombre.lower().endswith(".ots"):
                        encontrados.append(os.path.join(base, nombre))
        elif os.path.isfile(r) and r.lower().endswith(".ots"):
            encontrados.append(r)
        elif os.path.isfile(r) and os.path.exists(r + ".ots"):
            encontrados.append(r + ".ots")
    return sorted(set(encontrados))


def _imprime(info):
    print("-" * 78)
    print("PRUEBA:", info["ots"])
    if "error" in info:
        print("  ERROR:", info["error"])
        return
    print("  original:", info["original"])
    print("  algoritmo prueba:", info["algoritmo"])
    print("  digest sellado :", info["digest_prueba"])
    ef = info.get("estado_fichero")
    if ef == "ORIGINAL AUSENTE":
        print("  fichero actual : ORIGINAL AUSENTE (no se puede comparar)")
    else:
        print("  digest actual  :", info.get("digest_actual"))
        if ef == "COINCIDE":
            print("  INTEGRIDAD     : COINCIDE — la prueba corresponde al fichero actual")
        else:
            print("  INTEGRIDAD     : NO COINCIDE — el fichero cambió desde que se ancló")
            causa = info.get("causa_deriva")
            if causa:
                print("                   causa probable:", causa, "reproduce el digest sellado")
            else:
                print("                   (no explicado por finales de línea; cambio de contenido)")
    print("  ESTADO ANCLA   :", info.get("estado_ancla"))
    if info.get("pendientes"):
        print("    pendientes en:", ", ".join(info["pendientes"]))
    if info.get("bitcoin"):
        for cadena, altura in info["bitcoin"]:
            print("    confirmado en", cadena, "bloque", altura)
    if info.get("otras"):
        print("    otras atestaciones:", ", ".join(info["otras"]))


def main(argv):
    if len(argv) < 2:
        print("Uso: python herramientas/comprobar_anclas.py <carpeta-o-fichero> [...]")
        return 2
    ots = _buscar_ots(argv[1:])
    if not ots:
        print("No se encontraron ficheros .ots en las rutas dadas.")
        return 1
    print("Anclas encontradas:", len(ots))
    resumen = {"COINCIDE": 0, "NO COINCIDE": 0, "ORIGINAL AUSENTE": 0}
    estados = {"CONFIRMADO": 0, "PENDIENTE": 0, "SIN ATESTACION": 0}
    for ruta in ots:
        info = comprobar_ots(ruta)
        _imprime(info)
        if "error" not in info:
            resumen[info.get("estado_fichero", "ORIGINAL AUSENTE")] = \
                resumen.get(info.get("estado_fichero", "ORIGINAL AUSENTE"), 0) + 1
            estados[info["estado_ancla"]] = estados.get(info["estado_ancla"], 0) + 1
    print("=" * 78)
    print("RESUMEN integridad:", dict(resumen))
    print("RESUMEN anclaje   :", dict(estados))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
