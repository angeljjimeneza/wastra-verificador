# -*- coding: utf-8 -*-
# =============================================================================
# WASTRA · banco_ataques.py · Banco de ataques del verificador (Sprint 1)
# © 2026 Angel José Jiménez Álvarez (marca Bimeth). Todos los derechos reservados.
# Protocolo de refutación (canon V4): no afirmamos que el registro es fiable;
# lo atacamos y demostramos que cada ataque es DETECTADO por un tercero.
# =============================================================================
import json, os, shutil, subprocess, sys, tempfile

RAIZ = os.path.dirname(__file__)
DATA = os.path.join(RAIZ, "datos_ejemplo")
VERIF = os.path.join(RAIZ, "verificar.py")

def ejecutar_verificador(data_dir):
    env = dict(os.environ, WASTRA_DATA=data_dir)
    r = subprocess.run([sys.executable, VERIF], capture_output=True, text=True, env=env)
    return r.returncode, r.stdout

def copia_sandbox():
    tmp = tempfile.mkdtemp(prefix="wastra_ataque_")
    for fn in os.listdir(DATA):
        shutil.copy(os.path.join(DATA, fn), tmp)
    return tmp

def leer_eventos(d):
    with open(os.path.join(d, "eventos.jsonl")) as f:
        return [json.loads(l) for l in f if l.strip()]

def escribir_eventos(d, evs):
    with open(os.path.join(d, "eventos.jsonl"), "w") as f:
        for ev in evs:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")

ATAQUES = []
def ataque(nombre):
    def deco(fn):
        ATAQUES.append((nombre, fn)); return fn
    return deco

@ataque("A0 · Línea base: registro intacto debe verificar ÍNTEGRO")
def a0(d):
    rc, _ = ejecutar_verificador(d)
    return rc == 0

@ataque("A1 · Manipulación de contenido: cambiar el peso de una báscula")
def a1(d):
    evs = leer_eventos(d)
    for ev in evs:
        if ev["tipo"] == "LLEGADA_CDT" and "peso_bascula_t" in ev["payload"]:
            ev["payload"]["peso_bascula_t"] = 999.9  # fraude clásico de báscula
            break
    escribir_eventos(d, evs)
    rc, _ = ejecutar_verificador(d)
    return rc == 1

@ataque("A2 · Borrado retroactivo: eliminar un evento incómodo (la PARADA por amianto)")
def a2(d):
    evs = leer_eventos(d)
    evs = [e for e in evs if not (e["tipo"] == "PARADA_ACTIVADA" and e["payload"].get("causa") == "PAR-HAZ")]
    escribir_eventos(d, evs)
    rc, _ = ejecutar_verificador(d)
    return rc == 1

@ataque("A3 · Reordenación: demoler antes de la liberación forense")
def a3(d):
    evs = leer_eventos(d)
    idx = {e["id"]: i for i, e in enumerate(evs)}
    lote = next(e["lote_id"] for e in evs if e["tipo"] == "EMISION_LOTE")
    del_lote = [e for e in evs if e["lote_id"] == lote]
    lib = next(e for e in del_lote if e["tipo"] == "LIBERACION_FORENSE")
    emi = next(e for e in del_lote if e["tipo"] == "EMISION_LOTE")
    i, j = idx[lib["id"]], idx[emi["id"]]
    evs[i], evs[j] = evs[j], evs[i]
    escribir_eventos(d, evs)
    rc, _ = ejecutar_verificador(d)
    return rc == 1

@ataque("A4 · Certificado huérfano: certificar citando eventos inexistentes")
def a4(d):
    certs = json.load(open(os.path.join(d, "certificados.json")))
    certs[0]["eventos"].append("EV-2026-SIM-999999")
    json.dump(certs, open(os.path.join(d, "certificados.json"), "w"), ensure_ascii=False)
    rc, _ = ejecutar_verificador(d)
    return rc == 1

@ataque("A5 · Lote gemelo: certificado que roba eventos de otro lote")
def a5(d):
    certs = json.load(open(os.path.join(d, "certificados.json")))
    ajeno = certs[1]["eventos"][0]
    certs[0]["eventos"][0] = ajeno  # doble cobro del mismo material
    json.dump(certs, open(os.path.join(d, "certificados.json"), "w"), ensure_ascii=False)
    rc, _ = ejecutar_verificador(d)
    return rc == 1

@ataque("A6 · Falsificación de raíz: publicar una raíz Merkle 'corregida'")
def a6(d):
    raices = json.load(open(os.path.join(d, "merkle_raices.json")))
    dia = sorted(raices)[3]
    raices[dia]["raiz"] = "0" * 64
    json.dump(raices, open(os.path.join(d, "merkle_raices.json"), "w"))
    rc, _ = ejecutar_verificador(d)
    return rc == 1

@ataque("A7 · Inserción retroactiva: colar un evento fabricado en mitad de la cadena")
def a7(d):
    evs = leer_eventos(d)
    base = next(e for e in evs if e["tipo"] == "EMISION_LOTE")
    falso = dict(base)
    falso["id"] = "EV-2026-SIM-777777"
    falso["payload"] = dict(base["payload"], peso_estimado_t=0.1)
    # el atacante recalcula su propio hash pero no puede reescribir el resto de la cadena
    sys.path.insert(0, RAIZ)
    from nucleo import hash_evento
    falso["hash"] = hash_evento(falso)
    evs.insert(evs.index(base) + 1, falso)
    escribir_eventos(d, evs)
    rc, _ = ejecutar_verificador(d)
    return rc == 1

if __name__ == "__main__":
    print("WASTRA · banco de ataques — cada ataque debe ser DETECTADO por el verificador\n")
    resultados = []
    for nombre, fn in ATAQUES:
        d = copia_sandbox()
        try:
            ok = fn(d)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        resultados.append(ok)
        print(("  ✓ DETECTADO — " if ok else "  ✗ NO DETECTADO — ") + nombre if not nombre.startswith("A0")
              else ("  ✓ ÍNTEGRO — " if ok else "  ✗ FALLO BASE — ") + nombre)
    print(f"\n{sum(resultados)}/{len(resultados)} pruebas superadas")
    sys.exit(0 if all(resultados) else 1)
