# -*- coding: utf-8 -*-
"""Generador canónico de los vectores de prueba de ESPECIFICACION-FORMATO.md (§18).

Este script es la ÚNICA fuente de verdad de los valores del §18. Si la
especificación del formato cambia (estructura del evento, canonicalización,
árbol de Merkle), se regeneran los vectores ejecutando este fichero y se
trasladan sus resultados al documento. No se editan los hashes a mano.

Solo biblioteca estándar de Python (3.11+), exactamente como exige el formato:
el verificador debe poder ejecutarse sin instalar nada.

Uso:
    python herramientas/generar_vectores.py
"""
import hashlib
import json
import sys

CEROS = "0" * 64


def canonico(obj):
    """Serialización canónica wastra-json-canonico/1.0 (ver §4 de la spec)."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


# --- Tres eventos, con exactamente diez claves de nivel superior ------------
# id, secuencia, tipo, autor_id, dispositivo_id, ts_dispositivo, ts_servidor,
# payload, hash_anterior, hash. Todo dato de negocio (lote_id incluido) va
# DENTRO de payload; el nivel superior es cerrado (ver §8.1 de la spec).
def evento(campos_superiores):
    """Devuelve (dict_sin_hash, canonico, hash) para un evento dado."""
    s = canonico(campos_superiores)
    return campos_superiores, s, sha256_hex(s)


ev1 = {
    "autor_id": "OP-014",
    "dispositivo_id": "DEV-3391",
    "hash_anterior": CEROS,
    "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    "payload": {
        "descripcion": "Escombro mixto de demolición",
        "lote_id": "L-2026-0001",
        "origen": "Sector 7",
    },
    "secuencia": 1,
    "tipo": "ALTA_LOTE",
    "ts_dispositivo": "2026-09-01T10:00:00.000Z",
    "ts_servidor": "2026-09-01T12:03:11.000Z",
}
_, s1, h1 = evento(ev1)

ev2 = {
    "autor_id": "OP-014",
    "dispositivo_id": "DEV-3391",
    "hash_anterior": h1,
    "id": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
    "payload": {"lote_id": "L-2026-0001", "peso_g": 1234500, "unidad": "g"},
    "secuencia": 2,
    "tipo": "PESAJE",
    "ts_dispositivo": "2026-09-01T10:15:30.000Z",
    "ts_servidor": "2026-09-01T12:03:12.000Z",
}
_, s2, h2 = evento(ev2)

ev3 = {
    "autor_id": "OP-002",
    "dispositivo_id": "DEV-1180",
    "hash_anterior": h2,
    "id": "c3d4e5f6-a7b8-4c9d-8e0f-2a3b4c5d6e7f",
    "payload": {
        "corrige_evento_id": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
        "lote_id": "L-2026-0001",
        "motivo": "Peso corregido tras recalibración de báscula",
        "peso_g": 1230000,
        "unidad": "g",
    },
    "secuencia": 3,
    "tipo": "CORRECCION",
    "ts_dispositivo": "2026-09-01T11:00:00.000Z",
    "ts_servidor": "2026-09-01T12:30:00.000Z",
}
_, s3, h3 = evento(ev3)


# --- Merkle RFC 6962 --------------------------------------------------------
def mth_hoja(d):  # d = 32 bytes de la huella del evento
    return hashlib.sha256(b"\x00" + d).digest()


def mth_nodo(izq, der):
    return hashlib.sha256(b"\x01" + izq + der).digest()


def reconstruye(indice, num_hojas, hoja_hash_hex, ruta_hex):
    """Reconstrucción de la raíz según RFC 6962 §2.1.1 (ver §10.4 de la spec)."""
    fn = indice
    sn = num_hojas - 1
    r = mth_hoja(bytes.fromhex(hoja_hash_hex))
    pasos = []
    for p_hex in ruta_hex:
        s = bytes.fromhex(p_hex)
        if sn == 0:
            raise ValueError("ruta más larga de lo que el árbol admite")
        if (fn & 1) == 1 or fn == sn:
            r = mth_nodo(s, r)
            lado = "IZQUIERDA"
            if (fn & 1) == 0:
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = mth_nodo(r, s)
            lado = "DERECHA"
        pasos.append((lado, p_hex, r.hex(), fn, sn))
        fn >>= 1
        sn >>= 1
    return r.hex(), sn, pasos


def main():
    print("=== SERIALIZACIONES CANONICAS Y HASHES ===")
    for i, (s, h) in enumerate([(s1, h1), (s2, h2), (s3, h3)], 1):
        print(f"\n-- Evento {i} ({len(s)} bytes UTF-8) --")
        print(s.decode("utf-8"))
        print("sha256:", h)

    d0, d1, d2 = bytes.fromhex(h1), bytes.fromhex(h2), bytes.fromhex(h3)
    L0, L1, L2 = mth_hoja(d0), mth_hoja(d1), mth_hoja(d2)
    node01 = mth_nodo(L0, L1)  # MTH(D[0:2]); k=2 para n=3
    raiz = mth_nodo(node01, L2)  # MTH(D) = nodo(MTH(D[0:2]), MTH(D[2:3])=L2)

    print("\n=== ARBOL DE MERKLE (n=3, k=2) ===")
    print("L0     =", L0.hex())
    print("L1     =", L1.hex())
    print("L2     =", L2.hex())
    print("node01 =", node01.hex())
    print("raiz   =", raiz.hex())

    print("\n=== PRUEBA DE INCLUSION EVENTO 2 (indice 1, num_hojas 3) ===")
    ruta = [L0.hex(), L2.hex()]
    print("ruta =", ruta)
    recon, sn_final, pasos = reconstruye(1, 3, h2, ruta)
    for i, (lado, herm, res, fn, sn) in enumerate(pasos, 1):
        print(f"paso {i}: hermano {lado}, p={herm}")
        print(f"        r={res}  (fn={fn}, sn={sn})")
    print("sn_final =", sn_final, "(debe ser 0)")
    print("raiz reconstruida =", recon)
    print("coincide:", recon == raiz.hex())


if __name__ == "__main__":
    # UTF-8 en la salida pase lo que pase con la consola: los vectores llevan
    # acentos y al redirigirlos a un fichero se romperian.
    for _flujo in (sys.stdout, sys.stderr):
        if hasattr(_flujo, "reconfigure"):
            try:
                _flujo.reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass
    main()
