# -*- coding: utf-8 -*-
"""Genera un paquete `wastra-export/1.0` válido con datos ficticios realistas.

Escenario: la recepción de un lote de escombro de demolición en un Centro de
Tratamiento (CDT) durante dos días. Todos los datos son inventados (R-6).

El paquete resultante cumple las capas C1, C2 y C3 de la especificación al pie
de la letra: nivel superior cerrado a diez claves, canonicalización
wastra-json-canonico/1.0, cadena de huellas global, árbol de Merkle RFC 6962.
NO incluye anclas `.ots`: el anclaje (C4) es un módulo posterior y no se
fabrica una prueba OpenTimestamps ficticia. Un verificador informaría del
estado SIN ANCLA para cada día (§11.2 de la especificación).

Es la referencia contra la que se prueba el verificador: sin datos que
verificar no hay nada que demostrar.

Solo biblioteca estándar. Compatible con Python 3.9+ (R-1). Uso:

    python generar_ejemplo.py [salida.zip]
"""
import hashlib
import io
import json
import os
import sys
import zipfile

# --- Localización de la especificación a incrustar --------------------------
_RAIZ = os.path.dirname(os.path.abspath(__file__))
_SPEC = os.path.join(_RAIZ, "ESPECIFICACION-FORMATO.md")

CEROS = "0" * 64

# Texto canónico literal del aviso (§7.2 de la especificación). Debe coincidir
# carácter a carácter con el que el verificador lleva compilado.
AVISO = (
    "Este paquete acredita integridad, orden, autoría y anterioridad de las "
    "declaraciones registradas. No acredita la veracidad de su contenido."
)

# Espacio de nombres de tipos que declara este despliegue (§8.2).
TIPOS_DECLARADOS = [
    "ALTA_LOTE", "PESAJE", "MANIFIESTO", "RECEPCION", "PROCESADO",
    "CORRECCION", "ACCESO", "EXPORTACION",
]


# --- Canonicalización wastra-json-canonico/1.0 (§4) -------------------------
def _rechaza_flotantes(obj, ruta="raiz"):
    """Aborta si hay algún float a cualquier profundidad (§4, regla 5)."""
    if isinstance(obj, float):
        raise ValueError("coma flotante prohibida en " + ruta)
    if isinstance(obj, dict):
        for k, v in obj.items():
            _rechaza_flotantes(v, ruta + "." + str(k))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _rechaza_flotantes(v, ruta + "[" + str(i) + "]")


def canonico(obj):
    _rechaza_flotantes(obj)
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


# --- Árbol de Merkle RFC 6962 (§10) -----------------------------------------
def _k_menor(n):
    """Mayor potencia de 2 estrictamente menor que n."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _mth(hojas):
    """Merkle Tree Hash sobre una lista de hojas (cada una 32 bytes)."""
    n = len(hojas)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hashlib.sha256(b"\x00" + hojas[0]).digest()
    k = _k_menor(n)
    return hashlib.sha256(b"\x01" + _mth(hojas[:k]) + _mth(hojas[k:])).digest()


def _ruta(indice, hojas):
    """Camino de auditoría RFC 6962: huellas hermanas de la hoja, de abajo
    arriba. Sin campo de lado: el lado se deriva al verificar (§10.4)."""
    n = len(hojas)
    if n == 1:
        return []
    k = _k_menor(n)
    if indice < k:
        return _ruta(indice, hojas[:k]) + [_mth(hojas[k:])]
    return _ruta(indice - k, hojas[k:]) + [_mth(hojas[:k])]


# --- Eventos del ejemplo (deterministas) ------------------------------------
# Cada entrada define los campos del evento SIN hash, hash_anterior ni
# secuencia: esos se calculan al encadenar. `id` es UUID v4 fijo. `dia` es
# informativo; el día real lo fija ts_servidor en UTC (§13).
_PLANTILLA = [
    # --- Día 2026-09-01 ---
    {
        "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "tipo": "ALTA_LOTE",
        "autor_id": "OP-014", "dispositivo_id": "DEV-3391",
        "ts_dispositivo": "2026-09-01T08:12:04.000Z",
        "ts_servidor": "2026-09-01T08:44:57.000Z",
        "payload": {
            "descripcion": "Escombro mixto de demolición de forjado",
            "lote_id": "L-2026-0001",
            "origen": "Sector 7, manzana 14",
        },
    },
    {
        "id": "9b2f8c1e-3d4a-4b5c-8e6f-1a2b3c4d5e6f",
        "tipo": "PESAJE",
        "autor_id": "OP-014", "dispositivo_id": "DEV-3391",
        "ts_dispositivo": "2026-09-01T08:30:11.000Z",
        "ts_servidor": "2026-09-01T08:45:02.000Z",
        "payload": {
            "bascula_id": "BAS-02",
            "lote_id": "L-2026-0001",
            "peso_g": 8420000,
            "unidad": "g",
        },
    },
    {
        "id": "7c9e6a41-2b3c-4d5e-9f80-1122334455aa",
        "tipo": "MANIFIESTO",
        "autor_id": "OP-014", "dispositivo_id": "DEV-3391",
        "ts_dispositivo": "2026-09-01T09:05:40.000Z",
        "ts_servidor": "2026-09-01T09:20:15.000Z",
        "payload": {
            "destino_cdt": "CDT-CASTELLBISBAL-01",
            "lote_id": "L-2026-0001",
            "matricula": "1234-XYZ",
            "transportista": "TRANS-FICTICIA-SL",
        },
    },
    {
        "id": "3e1b2c4d-5f6a-4b7c-8d9e-0f1a2b3c4d5e",
        "tipo": "ACCESO",
        "autor_id": "OP-002", "dispositivo_id": "DEV-1180",
        "ts_dispositivo": "2026-09-01T14:02:00.000Z",
        "ts_servidor": "2026-09-01T14:02:03.000Z",
        "payload": {
            "lote_id": "L-2026-0001",
            "recurso": "expediente_lote",
            "resultado": "consulta",
        },
    },
    # --- Día 2026-09-02 ---
    {
        "id": "a2c4e6f8-1b3d-4f5a-9c7e-2d4f6a8c0e1b",
        "tipo": "RECEPCION",
        "autor_id": "OP-002", "dispositivo_id": "DEV-1180",
        "ts_dispositivo": "2026-09-02T07:48:22.000Z",
        "ts_servidor": "2026-09-02T07:48:25.000Z",
        "payload": {
            "cdt_id": "CDT-CASTELLBISBAL-01",
            "estado": "aceptado",
            "lote_id": "L-2026-0001",
        },
    },
    {
        "id": "b3d5f7a9-2c4e-4a6b-8d0f-3e5a7c9b1d2f",
        "tipo": "PESAJE",
        "autor_id": "OP-002", "dispositivo_id": "DEV-1180",
        "ts_dispositivo": "2026-09-02T07:55:10.000Z",
        "ts_servidor": "2026-09-02T07:55:13.000Z",
        "payload": {
            "bascula_id": "BAS-CDT-01",
            "lote_id": "L-2026-0001",
            "peso_g": 8395000,
            "unidad": "g",
        },
    },
    {
        "id": "c4e6a8b0-3d5f-4b7c-9e1a-4f6b8d0a2c3e",
        "tipo": "PROCESADO",
        "autor_id": "OP-007", "dispositivo_id": "DEV-2205",
        "ts_dispositivo": "2026-09-02T11:20:33.000Z",
        "ts_servidor": "2026-09-02T11:20:36.000Z",
        "payload": {
            "fraccion": "arido_reciclado_20_40",
            "lote_id": "L-2026-0001",
            "peso_g": 6100000,
            "unidad": "g",
        },
    },
    {
        "id": "d5f7b9c1-4e6a-4c8d-8f2b-5a7c9e1b3d4f",
        "tipo": "CORRECCION",
        "autor_id": "OP-007", "dispositivo_id": "DEV-2205",
        "ts_dispositivo": "2026-09-02T11:35:00.000Z",
        "ts_servidor": "2026-09-02T11:35:04.000Z",
        "payload": {
            # Corrige el pesaje de recepción (evento de secuencia 6).
            "corrige_evento_id": "b3d5f7a9-2c4e-4a6b-8d0f-3e5a7c9b1d2f",
            "lote_id": "L-2026-0001",
            "motivo": "Tara de la báscula mal fijada; peso neto corregido",
            "peso_g": 8360000,
            "unidad": "g",
        },
    },
    {
        "id": "e6a8c0d2-5f7b-4d9e-9a3c-6b8d0f2a4c5e",
        "tipo": "EXPORTACION",
        "autor_id": "OP-002", "dispositivo_id": "DEV-1180",
        "ts_dispositivo": "2026-09-02T18:00:00.000Z",
        "ts_servidor": "2026-09-02T18:00:00.000Z",
        "payload": {
            "destinatario": "auditoria_externa",
            "rango_desde": "2026-09-01",
            "rango_hasta": "2026-09-02",
        },
    },
]


def _dia_utc(ts_servidor):
    """Día AAAA-MM-DD derivado de ts_servidor en UTC (§13). El sufijo Z ya es
    UTC y el formato es estricto, así que basta con los diez primeros
    caracteres."""
    return ts_servidor[:10]


def construir_eventos():
    """Encadena la plantilla en eventos completos, con secuencia global desde 1,
    hash_anterior enlazado y hash calculado excluyendo la propia clave."""
    eventos = []
    hash_anterior = CEROS
    for i, base in enumerate(_PLANTILLA, start=1):
        evento = {
            "id": base["id"],
            "secuencia": i,
            "tipo": base["tipo"],
            "autor_id": base["autor_id"],
            "dispositivo_id": base["dispositivo_id"],
            "ts_dispositivo": base["ts_dispositivo"],
            "ts_servidor": base["ts_servidor"],
            "payload": base["payload"],
            "hash_anterior": hash_anterior,
        }
        h = sha256_hex(canonico(evento))  # hash sobre el evento SIN la clave hash
        evento["hash"] = h
        # Comprobación: exactamente diez claves de nivel superior (§8.1).
        assert len(evento) == 10, "el evento no tiene diez claves de nivel superior"
        eventos.append(evento)
        hash_anterior = h
    return eventos


def construir_merkle_por_dia(eventos):
    """Devuelve {dia: objeto merkle} con raíz, hojas y pruebas por evento."""
    por_dia = {}
    for ev in eventos:
        por_dia.setdefault(_dia_utc(ev["ts_servidor"]), []).append(ev)

    merkles = {}
    for dia, evs in por_dia.items():
        evs.sort(key=lambda e: e["secuencia"])  # orden de secuencia creciente
        hashes_hex = [e["hash"] for e in evs]
        hojas = [bytes.fromhex(h) for h in hashes_hex]
        raiz = _mth(hojas)
        pruebas = {}
        for indice, e in enumerate(evs):
            ruta = _ruta(indice, hojas)
            pruebas[e["id"]] = {
                "indice": indice,
                "ruta": [n.hex() for n in ruta],
            }
        merkles[dia] = {
            "fecha": dia,
            "raiz": raiz.hex(),
            "num_hojas": len(hojas),
            "hojas": hashes_hex,
            "pruebas": pruebas,
        }
    return merkles


def construir_manifiesto(eventos, dias, spec_bytes):
    # TODO: SELLADO — mientras SELLADO.md esté en BORRADOR, `especificacion_sha256`
    # se calcula aquí dinámicamente a partir de la copia incrustada. Al sellar,
    # esta huella DEBE coincidir con la versión sellada (la que el verificador
    # llevará compilada); este es el punto exacto que cambia de comportamiento.
    especificacion_sha256 = sha256_hex(spec_bytes)

    tipos_usados = {e["tipo"] for e in eventos}
    faltan = tipos_usados - set(TIPOS_DECLARADOS)
    assert not faltan, "hay tipos usados no declarados: " + repr(faltan)

    return {
        "formato": "wastra-export",
        "version": "1.0",
        "generado_en": "2026-09-02T18:05:00.000Z",
        "generador": "generar_ejemplo.py · datos ficticios",
        "rango": {"desde": dias[0], "hasta": dias[-1]},
        "num_eventos": len(eventos),
        "dias": dias,
        "tipos_declarados": TIPOS_DECLARADOS,
        "cadena": {
            "secuencia_desde": eventos[0]["secuencia"],
            "secuencia_hasta": eventos[-1]["secuencia"],
            "hash_anterior_esperado": eventos[0]["hash_anterior"],
            "hash_ultimo": eventos[-1]["hash"],
        },
        "algoritmo_huella": "SHA-256",
        "canonicalizacion": "wastra-json-canonico/1.0",
        "especificacion_sha256": especificacion_sha256,
        "merkle": "RFC6962",
        "anclaje": "OpenTimestamps",
        "titular": "Angel José Jiménez Álvarez",
        "aviso": AVISO,
    }


def generar(salida):
    if not os.path.exists(_SPEC):
        raise SystemExit("No se encuentra ESPECIFICACION-FORMATO.md junto al script")
    spec_bytes = io.open(_SPEC, "rb").read()

    carpeta = os.path.dirname(os.path.abspath(salida))
    if carpeta and not os.path.isdir(carpeta):
        os.makedirs(carpeta, exist_ok=True)

    eventos = construir_eventos()
    merkles = construir_merkle_por_dia(eventos)
    dias = sorted(merkles.keys())
    manifiesto = construir_manifiesto(eventos, dias, spec_bytes)

    # eventos.jsonl: un evento canónico por línea, en orden de secuencia.
    lineas = b"\n".join(canonico(e) for e in eventos) + b"\n"

    with zipfile.ZipFile(salida, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifiesto.json", canonico(manifiesto))
        z.writestr("ESPECIFICACION-FORMATO.md", spec_bytes)
        z.writestr("eventos/eventos.jsonl", lineas)
        for dia in dias:
            z.writestr("merkle/" + dia + ".json", canonico(merkles[dia]))
        # Sin anclas/*.ots: el anclaje (C4) es un módulo posterior; no se
        # fabrica una prueba OpenTimestamps ficticia (§11).

    return manifiesto, eventos, merkles


def main(argv):
    salida = argv[1] if len(argv) > 1 else "exportacion-ejemplo.zip"
    manifiesto, eventos, merkles = generar(salida)
    print("Paquete generado:", salida)
    print("  eventos:", len(eventos))
    print("  días:", ", ".join(sorted(merkles.keys())))
    for dia in sorted(merkles.keys()):
        m = merkles[dia]
        print("    " + dia + ": " + str(m["num_hojas"]) + " hojas, raíz " + m["raiz"][:16] + "…")
    print("  cadena:", manifiesto["cadena"]["secuencia_desde"], "->",
          manifiesto["cadena"]["secuencia_hasta"])
    print("  especificacion_sha256:", manifiesto["especificacion_sha256"][:16] + "…")
    print("  anclaje: SIN ANCLA (C4 se añade en el módulo de anclaje)")


if __name__ == "__main__":
    main(sys.argv)
