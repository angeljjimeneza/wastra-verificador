#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""banco_de_ataques.py - diez intentos de falsificar un registro WASTRA.

    python3 banco_de_ataques.py [paquete.zip]

Un verificador que siempre dice «correcto» no vale nada. Esta herramienta
fabrica diez paquetes deliberadamente corrompidos a partir de uno válido y
demuestra, delante de quien haga falta, en qué capa cae cada uno.

Los ataques no son caprichosos: son, uno por uno, las formas conocidas de
falsear un registro. Y están ordenados de menor a mayor sofisticación, porque
esa progresión **es** el argumento del sistema:

    A-01 a A-04   el atacante toca los datos            -> cae en C1/C2
    A-05          y además rehace TODA la cadena        -> cae en C3
    A-06          y además rehace TAMBIÉN las raíces    -> solo cae en C4
    A-07 a A-10   ataques a la envoltura y al anclaje   -> C1 y C4

**A-06 es la demostración central del proyecto.** Es el punto exacto en el que
un adversario con control total de la base de datos ha reconstruido todo de
forma internamente coherente —cadena impecable, raíces impecables— y aun así
no puede ganar, porque no puede reescribir lo que la cadena pública de Bitcoin
ya presenció. Si el paquete no lleva anclaje, A-06 **pasa**: y ese es
precisamente el resultado que hay que enseñar, porque explica para qué sirve
el anclaje mejor que cualquier discurso.

(c) 2026 Angel Jose Jimenez Alvarez (marca Bimeth). Licencia Apache-2.0.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, AQUI)

import verificar as V                                          # noqa: E402

ANCHO = 78


# =============================================================================
# Utilidades sobre el paquete
# =============================================================================

def leer_paquete(ruta):
    with zipfile.ZipFile(ruta) as z:
        return {n: z.read(n) for n in z.namelist() if not n.endswith("/")}


def escribir_paquete(ruta, contenido):
    with zipfile.ZipFile(ruta, "w", zipfile.ZIP_DEFLATED) as z:
        for nombre in sorted(contenido):
            z.writestr(nombre, contenido[nombre])


def eventos_de(contenido):
    texto = contenido[V.RUTA_EVENTOS].decode("utf-8")
    return [json.loads(l) for l in texto.split("\n") if l.strip()]


def poner_eventos(contenido, eventos):
    contenido[V.RUTA_EVENTOS] = b"\n".join(V.canonico(e) for e in eventos) + b"\n"
    return contenido


def manifiesto_de(contenido):
    return json.loads(contenido[V.RUTA_MANIFIESTO].decode("utf-8"))


def poner_manifiesto(contenido, m):
    contenido[V.RUTA_MANIFIESTO] = V.canonico(m)
    return contenido


def rehacer_cadena(eventos):
    """Recalcula hash_anterior y hash de todos los eventos, en orden.

    Es lo que haría un adversario con acceso de escritura a la base de datos:
    no hay ninguna magia aquí, y ese es el punto.
    """
    anterior = V.CEROS64 if eventos and eventos[0]["secuencia"] == 1 else eventos[0]["hash_anterior"]
    for ev in eventos:
        ev["hash_anterior"] = anterior
        ev.pop("hash", None)
        ev["hash"] = V.hash_evento(ev)
        anterior = ev["hash"]
    return eventos


def _ruta_merkle(indice, hojas):
    """Camino de auditoría RFC 6962 (mismas reglas que el generador)."""
    n = len(hojas)
    if n == 1:
        return []
    k = V._k_menor(n)
    if indice < k:
        return _ruta_merkle(indice, hojas[:k]) + [V.mth(hojas[k:])]
    return _ruta_merkle(indice - k, hojas[k:]) + [V.mth(hojas[:k])]


def rehacer_merkle(contenido, eventos):
    """Reconstruye TODOS los ficheros merkle/ para que cuadren con los eventos."""
    por_dia = {}
    for ev in eventos:
        por_dia.setdefault(ev["ts_servidor"][:10], []).append(ev)
    for nombre in [n for n in list(contenido) if n.startswith("merkle/")]:
        del contenido[nombre]
    for dia, evs in por_dia.items():
        evs.sort(key=lambda e: e["secuencia"])
        hashes = [e["hash"] for e in evs]
        hojas = [bytes.fromhex(h) for h in hashes]
        contenido["merkle/%s.json" % dia] = V.canonico({
            "fecha": dia,
            "raiz": V.mth(hojas).hex(),
            "num_hojas": len(hojas),
            "hojas": hashes,
            "pruebas": {e["id"]: {"indice": i,
                                  "ruta": [n.hex() for n in _ruta_merkle(i, hojas)]}
                        for i, e in enumerate(evs)},
        })
    return contenido


def rehacer_manifiesto(contenido, eventos):
    """Deja el manifiesto perfectamente coherente con los eventos alterados."""
    m = manifiesto_de(contenido)
    dias = sorted({e["ts_servidor"][:10] for e in eventos})
    m["num_eventos"] = len(eventos)
    m["dias"] = dias
    m["rango"] = {"desde": dias[0], "hasta": dias[-1]}
    m["cadena"] = {
        "secuencia_desde": eventos[0]["secuencia"],
        "secuencia_hasta": eventos[-1]["secuencia"],
        "hash_anterior_esperado": eventos[0]["hash_anterior"],
        "hash_ultimo": eventos[-1]["hash"],
    }
    return poner_manifiesto(contenido, m)


# =============================================================================
# Los diez ataques
# =============================================================================

ATAQUES = []


def ataque(codigo, titulo, historia, esperado):
    def deco(fn):
        ATAQUES.append({"codigo": codigo, "titulo": titulo, "historia": historia,
                        "esperado": esperado, "fn": fn})
        return fn
    return deco


@ataque("A-01", "Modificar un campo de un evento",
        "El operador declaró 1.234,5 t. Alguien lo cambia en la base de datos "
        "para que diga otra cosa, y no toca nada más.", "C2")
def a01(c):
    evs = eventos_de(c)
    objetivo = evs[len(evs) // 2]
    objetivo["autor_id"] = "OP-999-SUPLANTADO"
    return poner_eventos(c, evs)


@ataque("A-02", "Eliminar un evento intermedio",
        "Un pesaje incómodo desaparece del registro, como si nunca hubiera "
        "ocurrido.", "C2")
def a02(c):
    evs = eventos_de(c)
    del evs[len(evs) // 2]
    return poner_eventos(c, evs)


@ataque("A-03", "Insertar un evento fabricado",
        "Se cuela un pesaje que nunca ocurrió, en mitad de la historia, para "
        "inflar el tonelaje certificado.", "C2")
def a03(c):
    evs = eventos_de(c)
    falso = copy.deepcopy(evs[1])
    falso["id"] = "ffffffff-ffff-4fff-8fff-ffffffffffff"
    falso["payload"] = {"lote_id": "L-FABRICADO", "peso_g": 99000000, "unidad": "g"}
    evs.insert(2, falso)
    return poner_eventos(c, evs)


@ataque("A-04", "Reordenar dos eventos",
        "Se intercambian dos eventos para que la demolición parezca posterior "
        "a la liberación forense, y no al revés.", "C1/C2")
def a04(c):
    evs = eventos_de(c)
    evs[1], evs[2] = evs[2], evs[1]
    return poner_eventos(c, evs)


@ataque("A-05", "Modificar un evento y recalcular TODA la cadena",
        "El atacante ya sabe lo que hace: cambia el dato y rehace todos los "
        "enlaces de la cadena para que no quede ni una costura. Pero olvida "
        "las raíces de Merkle.", "C3")
def a05(c):
    evs = eventos_de(c)
    evs[len(evs) // 2]["payload"] = {"lote_id": "L-ALTERADO", "peso_g": 1, "unidad": "g"}
    evs = rehacer_cadena(evs)
    c = poner_eventos(c, evs)
    return rehacer_manifiesto(c, evs)


@ataque("A-06", "Modificar la cadena y recalcular TAMBIÉN las raíces de Merkle",
        "Control total de la base de datos. Cambia el dato, rehace la cadena, "
        "rehace las raíces y deja el manifiesto impecable. El paquete es, por "
        "dentro, perfecto. Lo único que no puede rehacer es lo que Bitcoin ya "
        "presenció.", "C4")
def a06(c):
    evs = eventos_de(c)
    evs[len(evs) // 2]["payload"] = {"lote_id": "L-REESCRITO", "peso_g": 1, "unidad": "g"}
    evs = rehacer_cadena(evs)
    c = poner_eventos(c, evs)
    c = rehacer_merkle(c, evs)
    return rehacer_manifiesto(c, evs)


@ataque("A-07", "Sustituir la prueba de anclaje por la de otro día",
        "La raíz de hoy no está anclada, así que se le pone encima el recibo "
        "de anteayer, que sí lo está.", "C4")
def a07(c):
    anclas = sorted(n for n in c if n.startswith("anclas/") and n.endswith(".ots"))
    if len(anclas) < 2:
        return None                                   # no demostrable sin dos anclas
    c[anclas[0]] = c[anclas[1]]
    return c


@ataque("A-08", "Truncar el paquete: un día entero desaparece",
        "Se exporta solo la parte cómoda de la historia y se omite un día "
        "completo, confiando en que nadie eche en falta lo que no ve.", "C1/C2")
def a08(c):
    evs = eventos_de(c)
    dias = sorted({e["ts_servidor"][:10] for e in evs})
    if len(dias) < 2:
        return None
    fuera = dias[0]
    evs = [e for e in evs if e["ts_servidor"][:10] != fuera]
    c.pop("merkle/%s.json" % fuera, None)
    c.pop("anclas/%s.ots" % fuera, None)
    c = poner_eventos(c, evs)
    return rehacer_manifiesto(c, evs)


@ataque("A-09", "CORRECCION que referencia un evento inexistente",
        "Se anota una corrección sobre un evento que no existe, para dejar "
        "constancia de una enmienda que nunca tuvo original.", "C1")
def a09(c):
    evs = eventos_de(c)
    falso = copy.deepcopy(evs[-1])
    falso["id"] = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    falso["secuencia"] = evs[-1]["secuencia"] + 1
    falso["tipo"] = "CORRECCION"
    falso["payload"] = {"corrige_evento_id": "00000000-0000-4000-8000-000000000000"}
    falso["hash_anterior"] = evs[-1]["hash"]
    falso.pop("hash", None)
    falso["hash"] = V.hash_evento(falso)
    evs.append(falso)
    m = manifiesto_de(c)
    if "CORRECCION" not in m.get("tipos_declarados", []):
        m["tipos_declarados"] = sorted(m.get("tipos_declarados", []) + ["CORRECCION"])
        c = poner_manifiesto(c, m)
    c = poner_eventos(c, evs)
    c = rehacer_merkle(c, evs)
    return rehacer_manifiesto(c, evs)


@ataque("A-10", "Duplicar el identificador de un evento",
        "Dos eventos con el mismo id: un lote que aparece dos veces y se "
        "certifica dos veces.", "C1")
def a10(c):
    evs = eventos_de(c)
    evs[-1]["id"] = evs[0]["id"]
    evs = rehacer_cadena(evs)
    c = poner_eventos(c, evs)
    c = rehacer_merkle(c, evs)
    return rehacer_manifiesto(c, evs)


@ataque("A-11", "Sustituir una fotografía conservando su nombre",
        "La foto del contenedor mostraba material peligroso mal segregado. "
        "Alguien la reemplaza por otra inocua y deja el mismo nombre de "
        "fichero, para que el evento la siga referenciando.", "C1")
def a11(c):
    """El adjunto se direcciona por contenido: el nombre ES la huella.

    Cambiar el contenido y conservar el nombre es, literalmente, mentir sobre
    la huella. C1 lo ve sin tener que mirar la foto: recalcula el SHA-256 del
    fichero y no coincide con el nombre que lleva puesto.
    """
    nombres = sorted(n for n in c if n.startswith("adjuntos/"))
    if not nombres:
        return None                      # el paquete no lleva adjuntos
    c[nombres[0]] = bytes([137, 80, 78, 71]) + b"fotografia sustituida" * 40
    return c


@ataque("A-12", "Ocultar una discrepancia: cambiar «discrepante» por «concordante»",
        "La máquina pesó una cosa y el oráculo declaró otra. El evento quedó "
        "marcado como discrepante. Alguien lo cambia a concordante para que "
        "nadie abra una no conformidad.", "C2")
def a12(c):
    """El ataque que justifica que modo_captura viva en el nivel superior.

    modo_captura entra en la serialización canónica del evento y por tanto en
    su hash. Cambiar «discrepante» por «concordante» cambia el hash, y C2 lo
    detecta sin necesidad de saber qué discrepaba.

    Si el atacante recalcula la cadena, cae en C3; si recalcula también las
    raíces, cae en C4. Es el mismo camino que A-05 y A-06, aplicado al campo
    que dice si hubo desacuerdo.
    """
    evs = eventos_de(c)
    objetivo = None
    for ev in evs:
        if ev.get("modo_captura") == "discrepante":
            objetivo = ev
            break
    if objetivo is None:
        return None                      # el paquete no registra discrepancias
    objetivo["modo_captura"] = "concordante"
    return poner_eventos(c, evs)


# =============================================================================
# Ejecución
# =============================================================================

def ejecutar_verificador(ruta, con_anclaje):
    cmd = [sys.executable, os.path.join(AQUI, "verificar.py"), ruta, "--json"]
    if con_anclaje:
        cmd.append("--con-anclaje")
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    try:
        return json.loads(r.stdout), r.returncode
    except ValueError:
        return None, r.returncode


def capas_en_fallo(informe):
    return [c["capa"] for c in informe["capas"] if c["estado"] == "FALLO"]


def primer_motivo(informe):
    for c in informe["capas"]:
        if c["estado"] == "FALLO" and c["fallos"]:
            return c["capa"], c["fallos"][0]["mensaje"]
    return None, None


def separador(ch="─"):
    return ch * ANCHO


def main():
    ap = argparse.ArgumentParser(description="Diez intentos de falsificar un registro WASTRA.")
    ap.add_argument("paquete", nargs="?", default="exportacion-ejemplo.zip")
    ap.add_argument("--con-anclaje", action="store_true",
                    help="ejecuta también la capa C4 (requiere red)")
    ap.add_argument("--conservar", metavar="CARPETA",
                    help="deja los paquetes corrompidos en esa carpeta, para inspeccionarlos")
    args = ap.parse_args()

    if not os.path.exists(args.paquete):
        print("No encuentro el paquete: %s" % args.paquete)
        print("Genérelo primero con:  python generar_ejemplo.py")
        return 3

    print()
    print("  BANCO DE ATAQUES · WASTRA")
    print("  %s" % separador("═"))
    print("  Paquete de partida: %s" % os.path.basename(args.paquete))
    print("  Capa 4 (anclaje):   %s" % ("activada" if args.con_anclaje else "NO ejecutada"))
    print()
    print("  Un verificador que siempre dice «correcto» no vale nada.")
    print("  Esto demuestra qué detecta, y en qué capa.")
    print()

    base, _ = ejecutar_verificador(args.paquete, args.con_anclaje)
    if base is None:
        print("  El paquete de partida no se puede verificar. Revíselo antes.")
        return 3
    if capas_en_fallo(base):
        print("  ATENCIÓN: el paquete de partida YA falla. El banco necesita")
        print("  un paquete íntegro para tener sentido.")
        return 3
    print("  Línea base: el paquete íntegro verifica CORRECTO. Empezamos.")
    print()

    tmp = args.conservar or tempfile.mkdtemp(prefix="wastra_ataques_")
    if not os.path.isdir(tmp):
        os.makedirs(tmp)

    resultados = []
    for a in ATAQUES:
        contenido = leer_paquete(args.paquete)
        alterado = a["fn"](contenido)
        if alterado is None:
            resultados.append({"a": a, "estado": "NO_APLICABLE",
                               "detalle": "el paquete de partida no reúne las condiciones"})
            continue
        ruta = os.path.join(tmp, "%s.zip" % a["codigo"].replace("-", ""))
        escribir_paquete(ruta, alterado)
        informe, codigo_salida = ejecutar_verificador(ruta, args.con_anclaje)
        if informe is None:
            resultados.append({"a": a, "estado": "MALFORMADO",
                               "detalle": "el paquete quedó tan roto que no se puede ni abrir",
                               "capas": [], "salida": codigo_salida})
            continue
        capas = capas_en_fallo(informe)
        capa, motivo = primer_motivo(informe)
        resultados.append({"a": a, "estado": "DETECTADO" if capas else "NO_DETECTADO",
                           "capas": capas, "capa": capa, "motivo": motivo,
                           "salida": codigo_salida, "ruta": ruta})

    # ---- salida presentable -------------------------------------------
    print("  %-6s %-46s %-9s %s" % ("", "ATAQUE", "ESPERADO", "RESULTADO"))
    print("  %s" % separador())
    for r in resultados:
        a = r["a"]
        if r["estado"] == "DETECTADO":
            marca = "DETECTADO en %s" % ",".join(r["capas"])
        elif r["estado"] == "MALFORMADO":
            marca = "RECHAZADO (malformado)"
        elif r["estado"] == "NO_APLICABLE":
            marca = "no demostrable aquí"
        else:
            marca = "NO DETECTADO"
        print("  %-6s %-46s %-9s %s" % (a["codigo"], a["titulo"][:46], a["esperado"], marca))
    print()

    # ---- el detalle de cada uno ---------------------------------------
    for r in resultados:
        a = r["a"]
        print("  %s" % separador())
        print("  %s · %s" % (a["codigo"], a["titulo"]))
        print()
        for linea in _envolver(a["historia"], ANCHO - 6):
            print("    %s" % linea)
        print()
        if r["estado"] == "DETECTADO":
            print("    Detectado en: %s   (código de salida %d)" % (
                ", ".join(r["capas"]), r["salida"]))
            for linea in _envolver("El verificador dice: «%s»" % r["motivo"], ANCHO - 6):
                print("    %s" % linea)
        elif r["estado"] == "MALFORMADO":
            print("    El paquete quedó irrecuperable: el verificador lo rechaza")
            print("    antes de poder analizarlo. También es una defensa.")
        elif r["estado"] == "NO_APLICABLE":
            print("    No demostrable con este paquete: %s." % r["detalle"])
        else:
            print("    *** NO DETECTADO ***")
            if a["esperado"] == "C4":
                for linea in _envolver(
                        "Y esto es exactamente lo que había que enseñar. El paquete es, "
                        "por dentro, impecable: la cadena cuadra, las raíces cuadran y el "
                        "manifiesto no miente sobre nada de lo que contiene. Ninguna "
                        "comprobación interna puede atraparlo, porque no hay nada "
                        "internamente incoherente que atrapar. La única defensa posible "
                        "es la capa 4: la raíz que Bitcoin presenció aquel día no es esta. "
                        "Sin anclaje, este ataque gana.", ANCHO - 6):
                    print("    %s" % linea)
            else:
                print("    Esto es un fallo del verificador y hay que corregirlo.")
        print()

    # ---- veredicto ------------------------------------------------------
    detectados = [r for r in resultados if r["estado"] in ("DETECTADO", "MALFORMADO")]
    no_detectados = [r for r in resultados if r["estado"] == "NO_DETECTADO"]
    no_aplicables = [r for r in resultados if r["estado"] == "NO_APLICABLE"]
    fallos_reales = [r for r in no_detectados if r["a"]["esperado"] != "C4"]

    print("  %s" % separador("═"))
    print("  RESULTADO: %d detectados · %d no detectados · %d no demostrables aquí"
          % (len(detectados), len(no_detectados), len(no_aplicables)))
    print()
    if fallos_reales:
        print("  HAY FALLOS REALES DEL VERIFICADOR:")
        for r in fallos_reales:
            print("    %s %s" % (r["a"]["codigo"], r["a"]["titulo"]))
        print()
        print("  Un ataque no detectado es un fallo del proyecto, no de la prueba.")
    elif no_detectados and not args.con_anclaje:
        print("  Los ataques que han pasado son los que SOLO la capa 4 puede")
        print("  detectar, y la capa 4 no se ha ejecutado. Vuelva a lanzarlo con")
        print("  --con-anclaje sobre un paquete anclado y no pasará ninguno.")
        print()
        print("  Mientras tanto, eso que acaba de ver es el argumento entero de")
        print("  WASTRA: un adversario con control total del registro puede dejarlo")
        print("  todo internamente perfecto. Lo único que no puede reescribir es")
        print("  lo que la cadena pública ya presenció.")
    else:
        print("  Los diez ataques caen. El registro no se puede falsear sin que")
        print("  se note, y se nota diciendo qué, dónde y por qué.")
    print()
    if not args.conservar:
        shutil.rmtree(tmp, ignore_errors=True)
    else:
        print("  Paquetes corrompidos conservados en: %s" % tmp)
        print()
    return 1 if fallos_reales else 0


def _envolver(texto, ancho):
    palabras, linea, salida = texto.split(), "", []
    for p in palabras:
        if len(linea) + len(p) + 1 > ancho:
            salida.append(linea)
            linea = p
        else:
            linea = (linea + " " + p).strip()
    if linea:
        salida.append(linea)
    return salida


if __name__ == "__main__":
    # UTF-8 en la salida pase lo que pase con la consola: en Windows no lo es
    # por defecto, y al redirigir el informe a un fichero los acentos se rompen.
    for _flujo in (sys.stdout, sys.stderr):
        if hasattr(_flujo, "reconfigure"):
            try:
                _flujo.reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass
    sys.exit(main())
