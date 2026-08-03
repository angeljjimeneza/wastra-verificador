# -*- coding: utf-8 -*-
# =============================================================================
# WASTRA · verificar.py · Verificador público (Sprint 1, demo v1)
# © 2026 Angel José Jiménez Álvarez (marca Bimeth). Todos los derechos reservados.
# Este verificador es el producto de confianza: cualquier tercero debe poder
# ejecutarlo sin cuenta y sin permiso, y llegar a la misma conclusión.
# Comprobaciones: C1 cadena por lote · C2 inclusión Merkle · C3 certificado.
# =============================================================================
"""Uso:
  python verificar.py                     -> verifica el registro completo
  python verificar.py CERT-2026-SIM-0007  -> verifica un certificado
  python verificar.py WSTR-...-L0042      -> verifica la cadena de un lote
Códigos de salida: 0 = ÍNTEGRO · 1 = ALTERACIÓN DETECTADA · 2 = error de uso
"""
import json, os, sys

sys.path.insert(0, os.path.dirname(__file__))
from nucleo import hash_evento, raiz_merkle, verificar_prueba_merkle, sha256_hex, json_canonico

BASE = os.environ.get("WASTRA_DATA", os.path.join(os.path.dirname(__file__), "datos_ejemplo"))

ORDEN_VALIDO = {
    "EVALUACION_REGISTRADA": {"__inicio__"},
    "AUTORIZACION_EMITIDA": {"EVALUACION_REGISTRADA"},
    "LIBERACION_FORENSE": {"AUTORIZACION_EMITIDA"},
    "EMISION_LOTE": {"LIBERACION_FORENSE"},
    "SALIDA_TRANSPORTE": {"EMISION_LOTE"},
    "LLEGADA_CDT": {"SALIDA_TRANSPORTE"},
    "INICIO_PROCESO": {"LLEGADA_CDT"},
    "PRODUCTO_GENERADO": {"INICIO_PROCESO"},
    "CERTIFICADO_EMITIDO": {"PRODUCTO_GENERADO"},
    "CIERRE_CICLO": {"CERTIFICADO_EMITIDO"},
    "PARADA_ACTIVADA": {"LLEGADA_CDT", "INICIO_PROCESO", "EMISION_LOTE"},
    "PARADA_LEVANTADA": {"PARADA_ACTIVADA"},
    "BLOQUEO_INVESTIGACION": {"SALIDA_TRANSPORTE", "EMISION_LOTE", "LLEGADA_CDT"},
    "DERIVACION_PELIGROSO": {"PARADA_ACTIVADA"},
    "DESTINO_FINAL_SEGURO": {"DERIVACION_PELIGROSO"},
}

def cargar():
    eventos = []
    with open(os.path.join(BASE, "eventos.jsonl")) as f:
        for linea in f:
            if linea.strip():
                eventos.append(json.loads(linea))
    raices = json.load(open(os.path.join(BASE, "merkle_raices.json")))
    certs = json.load(open(os.path.join(BASE, "certificados.json")))
    return eventos, raices, certs

def c1_cadena_lote(eventos_lote, hash_genesis, fallos):
    """C1: integridad y encadenamiento de los eventos de un lote."""
    previo = hash_genesis
    tipo_previo = "__inicio__"
    for ev in eventos_lote:
        if hash_evento(ev) != ev["hash"]:
            fallos.append(f"C1 {ev['lote_id']} {ev['id']}: hash no coincide — CONTENIDO ALTERADO")
            return
        if ev["hash_anterior"] != previo:
            fallos.append(f"C1 {ev['lote_id']} {ev['id']}: cadena rota — evento eliminado, insertado o reordenado")
            return
        permitidos = ORDEN_VALIDO.get(ev["tipo"], set())
        if permitidos and tipo_previo not in permitidos:
            fallos.append(f"C1 {ev['lote_id']} {ev['id']}: transición inválida {tipo_previo} → {ev['tipo']} (guarda C12-01)")
            return
        previo = ev["hash"]
        tipo_previo = ev["tipo"]

def c2_merkle(eventos, raices, fallos):
    """C2: cada raíz diaria publicada se recompone desde los eventos."""
    por_dia = {}
    for ev in eventos:
        por_dia.setdefault(ev["ts_servidor"][:10], []).append(ev["hash"])
    for dia, info in raices.items():
        recalculada = raiz_merkle(por_dia.get(dia, []))
        if recalculada != info["raiz"]:
            fallos.append(f"C2 {dia}: raíz Merkle publicada no coincide con los eventos — LOTE DIARIO ALTERADO")
        if len(por_dia.get(dia, [])) != info["n_eventos"]:
            fallos.append(f"C2 {dia}: número de eventos ({len(por_dia.get(dia, []))}) distinto del publicado ({info['n_eventos']})")

def c3_certificado(cert, indice_eventos, fallos):
    """C3: el certificado se sostiene sobre eventos íntegros e incluidos en Merkle."""
    limpio = {k: v for k, v in cert.items() if k != "hash"}
    if sha256_hex(json_canonico(limpio)) != cert["hash"]:
        fallos.append(f"C3 {cert['cert_id']}: hash del certificado no coincide — CERTIFICADO ALTERADO")
        return
    for ev_id in cert["eventos"]:
        ev = indice_eventos.get(ev_id)
        if ev is None:
            fallos.append(f"C3 {cert['cert_id']}: cita el evento {ev_id} que NO existe en el registro — CERTIFICADO HUÉRFANO")
            continue
        if ev["lote_id"] != cert["lote_id"]:
            fallos.append(f"C3 {cert['cert_id']}: el evento {ev_id} pertenece a otro lote — LOTE GEMELO")
            continue
        ref = cert["merkle"].get(ev_id)
        if not ref or not verificar_prueba_merkle(ev["hash"], ref["prueba"], ref["raiz"]):
            fallos.append(f"C3 {cert['cert_id']}: prueba Merkle inválida para {ev_id}")

def verificar_todo(objetivo=None):
    eventos, raices, certs = cargar()
    indice = {ev["id"]: ev for ev in eventos}
    por_lote = {}
    genesis = None
    for ev in eventos:
        if ev["tipo"] == "ESPACIO_GENESIS":
            genesis = ev
        elif ev["lote_id"]:
            por_lote.setdefault(ev["lote_id"], []).append(ev)
    fallos = []
    if genesis is None or hash_evento(genesis) != genesis["hash"]:
        fallos.append("C1 GÉNESIS: evento génesis ausente o alterado")
        return fallos, 0, 0
    if objetivo and objetivo.startswith("CERT-"):
        cert = next((c for c in certs if c["cert_id"] == objetivo), None)
        if not cert:
            print(f"Certificado {objetivo} no encontrado"); sys.exit(2)
        c1_cadena_lote(por_lote.get(cert["lote_id"], []), genesis["hash"], fallos)
        c3_certificado(cert, indice, fallos)
        return fallos, 1, 1
    if objetivo:  # lote
        if objetivo not in por_lote:
            print(f"Lote {objetivo} no encontrado"); sys.exit(2)
        c1_cadena_lote(por_lote[objetivo], genesis["hash"], fallos)
        return fallos, 1, 0
    for lote_id, evs in por_lote.items():
        c1_cadena_lote(evs, genesis["hash"], fallos)
    c2_merkle(eventos, raices, fallos)
    for cert in certs:
        c3_certificado(cert, indice, fallos)
    return fallos, len(por_lote), len(certs)

if __name__ == "__main__":
    objetivo = sys.argv[1] if len(sys.argv) > 1 else None
    fallos, n_lotes, n_certs = verificar_todo(objetivo)
    print(f"WASTRA · verificador — lotes: {n_lotes} · certificados: {n_certs}")
    if fallos:
        print(f"RESULTADO: ALTERACIÓN DETECTADA ({len(fallos)} hallazgos)")
        for f_ in fallos[:20]:
            print("  ✗", f_)
        sys.exit(1)
    print("RESULTADO: REGISTRO ÍNTEGRO — todo evento verificado (C1 cadena · C2 Merkle · C3 certificados)")
    sys.exit(0)
