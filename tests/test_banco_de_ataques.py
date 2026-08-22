# -*- coding: utf-8 -*-
"""Los diez ataques deben caer. Siempre. En cada cambio.

    pytest tests/test_banco_de_ataques.py -v

Este fichero es la red de seguridad del proyecto entero. El banco de ataques
demuestra que el verificador detecta; estas pruebas demuestran que **sigue**
detectando despues de cada cambio. Sin ellas, una refactorizacion bienintencionada
puede romper una deteccion sin que nadie se entere hasta que sea tarde.

Regla del proyecto: **un ataque no detectado es un fallo del proyecto, no de la
prueba.** Si una de estas pruebas se pone en rojo, no se ajusta la prueba: se
arregla el verificador.

Las pruebas de anclaje (A-06 y A-07) necesitan que el paquete lleve `.ots`. Si no
los lleva, se omiten con un motivo explicito en lugar de dar un falso verde.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import zipfile

import pytest

AQUI = os.path.dirname(os.path.abspath(__file__))
RAIZ = os.path.dirname(AQUI)
sys.path.insert(0, RAIZ)

import banco_de_ataques as B                                   # noqa: E402
import verificar as V                                          # noqa: E402

PAQUETE = os.path.join(RAIZ, "exportacion-ejemplo.zip")


# =============================================================================
# Preparacion
# =============================================================================

@pytest.fixture(scope="session")
def paquete():
    """Genera el paquete de ejemplo si no existe."""
    if not os.path.exists(PAQUETE):
        subprocess.run([sys.executable, os.path.join(RAIZ, "generar_ejemplo.py")],
                       cwd=RAIZ, check=True, capture_output=True)
    assert os.path.exists(PAQUETE), "no se pudo generar el paquete de ejemplo"
    return PAQUETE


@pytest.fixture(scope="session")
def tiene_anclas(paquete):
    with zipfile.ZipFile(paquete) as z:
        return any(n.startswith("anclas/") and n.endswith(".ots") for n in z.namelist())


def _verificar(ruta, con_anclaje=False):
    """Ejecuta el verificador y devuelve (informe, codigo_de_salida)."""
    cmd = [sys.executable, os.path.join(RAIZ, "verificar.py"), ruta, "--json"]
    if con_anclaje:
        cmd.append("--con-anclaje")
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", cwd=RAIZ)
    try:
        return json.loads(r.stdout), r.returncode
    except ValueError:
        return None, r.returncode


def _capas_en_fallo(informe):
    return {c["capa"] for c in informe["capas"] if c["estado"] == "FALLO"}


def _corromper(paquete, tmp_path, fn, nombre):
    """Aplica un ataque al paquete y devuelve la ruta del resultado, o None."""
    contenido = B.leer_paquete(paquete)
    alterado = fn(contenido)
    if alterado is None:
        return None
    destino = str(tmp_path / ("%s.zip" % nombre))
    B.escribir_paquete(destino, alterado)
    return destino


# =============================================================================
# Linea base: sin ella, nada de lo demas significa nada
# =============================================================================

def test_el_paquete_intacto_verifica_correcto(paquete):
    """Si la linea base fallara, todas las detecciones serian ruido."""
    informe, salida = _verificar(paquete)
    assert informe is not None, "el verificador no devolvio JSON"
    assert _capas_en_fallo(informe) == set(), \
        "el paquete de ejemplo intacto NO deberia fallar en ninguna capa"
    assert informe["veredicto"] == "CORRECTO"
    assert salida == 0, "un paquete integro debe salir con codigo 0"


def test_el_informe_lleva_el_aviso_del_verificador(paquete):
    """El aviso es el del verificador compilado, nunca el del paquete (§7.2)."""
    informe, _ = _verificar(paquete)
    assert informe["aviso"] == V.AVISO_CANONICO
    assert "No acredita la veracidad" in informe["aviso"]


def test_titular_y_generador_van_marcados_como_no_verificados(paquete):
    """§7.3: son manifestaciones sin valor probatorio y hay que decirlo."""
    informe, _ = _verificar(paquete)
    assert "declarado_no_verificado" in informe
    assert "titular" in informe["declarado_no_verificado"]


# =============================================================================
# Los diez ataques
# =============================================================================

CASOS_SIN_ANCLAJE = [
    ("A-01", B.a01, {"C2"}, "modificar un campo de un evento"),
    ("A-02", B.a02, {"C2"}, "eliminar un evento intermedio"),
    ("A-03", B.a03, {"C2"}, "insertar un evento fabricado"),
    ("A-04", B.a04, {"C1", "C2"}, "reordenar dos eventos"),
    ("A-05", B.a05, {"C3"}, "modificar y recalcular toda la cadena"),
    ("A-08", B.a08, {"C1", "C2"}, "truncar el paquete: falta un dia"),
    ("A-09", B.a09, {"C1"}, "CORRECCION a un evento inexistente"),
    ("A-10", B.a10, {"C1"}, "duplicar el id de un evento"),
]


@pytest.mark.parametrize("codigo,fn,capas_posibles,descripcion", CASOS_SIN_ANCLAJE,
                         ids=[c[0] for c in CASOS_SIN_ANCLAJE])
def test_ataque_detectado(paquete, tmp_path, codigo, fn, capas_posibles, descripcion):
    """Cada ataque debe caer, y caer en la capa que le corresponde."""
    ruta = _corromper(paquete, tmp_path, fn, codigo)
    if ruta is None:
        pytest.skip("%s no es demostrable con este paquete de ejemplo" % codigo)

    informe, salida = _verificar(ruta)
    assert informe is not None, "%s dejo el paquete ilegible" % codigo

    fallos = _capas_en_fallo(informe)
    assert fallos, "%s (%s) NO fue detectado. Es un fallo del proyecto." % (codigo, descripcion)
    assert fallos & capas_posibles, (
        "%s (%s) se detecto en %s, pero deberia caer al menos en una de %s"
        % (codigo, descripcion, sorted(fallos), sorted(capas_posibles)))
    assert salida == 1, "un paquete alterado debe salir con codigo 1"


# =============================================================================
# A-06 y A-07: solo el anclaje los detiene
# =============================================================================

def test_a06_supera_las_capas_internas(paquete, tmp_path):
    """La demostracion central del proyecto.

    A-06 rehace la cadena Y las raices Y el manifiesto. El paquete queda
    internamente impecable: C1, C2 y C3 no tienen nada que reprochar, porque no
    hay ninguna incoherencia interna que encontrar. **Que pase C1-C3 no es un
    defecto del verificador: es el hecho que justifica que exista C4.**
    """
    ruta = _corromper(paquete, tmp_path, B.a06, "A06")
    assert ruta is not None

    informe, _ = _verificar(ruta)          # sin --con-anclaje
    fallos = _capas_en_fallo(informe)
    internas = fallos & {"C1", "C2", "C3"}
    assert internas == set(), (
        "A-06 deberia superar todas las comprobaciones internas y ha fallado en %s. "
        "O el ataque esta mal construido, o el verificador esta detectando algo "
        "que no deberia poder detectar sin anclaje." % sorted(internas))


def test_a06_cae_en_c4(paquete, tmp_path, tiene_anclas):
    """Y con anclaje, cae. Ese es el argumento entero del sistema."""
    if not tiene_anclas:
        pytest.skip("el paquete no lleva anclas/*.ots: selle las raices para "
                    "poder demostrar A-06")
    ruta = _corromper(paquete, tmp_path, B.a06, "A06c4")
    informe, salida = _verificar(ruta, con_anclaje=True)
    assert informe is not None
    assert "C4" in _capas_en_fallo(informe), (
        "A-06 NO fue detectado en C4. Sin esta deteccion, el anclaje no aporta "
        "nada y el argumento central del proyecto se cae.")
    assert salida == 1


def test_a07_anclaje_de_otro_dia_cae_en_c4(paquete, tmp_path, tiene_anclas):
    if not tiene_anclas:
        pytest.skip("el paquete no lleva anclas/*.ots")
    ruta = _corromper(paquete, tmp_path, B.a07, "A07")
    if ruta is None:
        pytest.skip("hacen falta al menos dos dias anclados")
    informe, _ = _verificar(ruta, con_anclaje=True)
    assert "C4" in _capas_en_fallo(informe), \
        "sustituir el anclaje por el de otro dia debe caer en C4"


def test_el_anclaje_es_sobre_los_bytes_de_la_raiz(paquete, tiene_anclas):
    """§11: la prueba se hace sobre los 32 bytes de la raiz, NUNCA sobre su hex.

    Es el error de interoperabilidad mas frecuente y el que mas caro sale:
    un paquete sellado sobre el texto hexadecimal no lo detecta nadie hasta que
    otro verificador, escrito en otro lenguaje, no cuadra.
    """
    if not tiene_anclas:
        pytest.skip("el paquete no lleva anclas/*.ots")
    import binascii
    import anclaje

    contenido = B.leer_paquete(paquete)
    comprobados = 0
    for nombre in contenido:
        if not (nombre.startswith("merkle/") and nombre.endswith(".json")):
            continue
        dia = nombre[len("merkle/"):-len(".json")]
        ruta_ots = "anclas/%s.ots" % dia
        if ruta_ots not in contenido:
            continue
        raiz_hex = json.loads(contenido[nombre].decode("utf-8"))["raiz"]
        dtf = anclaje.leer_ots(contenido[ruta_ots])
        assert dtf.file_digest == binascii.unhexlify(raiz_hex), (
            "el anclaje de %s no se hizo sobre los 32 bytes de la raiz" % dia)
        assert dtf.file_digest != raiz_hex.encode("ascii"), (
            "el anclaje de %s se hizo sobre el TEXTO hexadecimal: error de "
            "interoperabilidad de §11" % dia)
        comprobados += 1
    assert comprobados > 0, "no habia ningun dia con ancla que comprobar"


# =============================================================================
# Ataques al fichero adjunto (extension 1.1)
# =============================================================================

def _primer_adjunto(contenido):
    for n in contenido:
        if n.startswith(V.PREFIJO_ADJUNTOS):
            return n
    return None


def test_foto_sustituida_cae_en_c1(paquete, tmp_path):
    """Un pesaje tecleado vale lo que valga la foto que lo respalda."""
    def ataque(c):
        n = _primer_adjunto(c)
        if n is None:
            return None
        c[n] = b"FOTO SUSTITUIDA DESPUES DEL REGISTRO"
        return c
    ruta = _corromper(paquete, tmp_path, ataque, "foto_sustituida")
    if ruta is None:
        pytest.skip("el paquete no lleva adjuntos")
    informe, salida = _verificar(ruta)
    assert "C1" in _capas_en_fallo(informe)
    assert salida == 1


def test_foto_ausente_cae_en_c1(paquete, tmp_path):
    def ataque(c):
        n = _primer_adjunto(c)
        if n is None:
            return None
        del c[n]
        return c
    ruta = _corromper(paquete, tmp_path, ataque, "foto_ausente")
    if ruta is None:
        pytest.skip("el paquete no lleva adjuntos")
    informe, _ = _verificar(ruta)
    assert "C1" in _capas_en_fallo(informe)


def test_fichero_huerfano_cae_en_c1(paquete, tmp_path):
    """Un paquete no es un sitio donde dejar cosas sueltas."""
    def ataque(c):
        c[V.PREFIJO_ADJUNTOS + "0" * 64] = b"fichero que nadie declara"
        return c
    ruta = _corromper(paquete, tmp_path, ataque, "huerfano")
    informe, _ = _verificar(ruta)
    assert "C1" in _capas_en_fallo(informe)


# =============================================================================
# Ataques al manifiesto y a la autodescripcion
# =============================================================================

def test_aviso_alterado_cae_en_c1(paquete, tmp_path):
    """El aviso es literal. Un caracter de diferencia invalida el paquete (§7.2)."""
    def ataque(c):
        m = B.manifiesto_de(c)
        m["aviso"] = m["aviso"].replace("No acredita", "Acredita")
        return B.poner_manifiesto(c, m)
    ruta = _corromper(paquete, tmp_path, ataque, "aviso")
    informe, _ = _verificar(ruta)
    assert "C1" in _capas_en_fallo(informe)


def test_especificacion_incrustada_alterada_cae_en_c1(paquete, tmp_path):
    """Si se puede reescribir la especificacion que viaja dentro, el paquete
    deja de autodescribirse y puede decir de si mismo lo que quiera (§16)."""
    def ataque(c):
        c[V.RUTA_ESPEC] = c[V.RUTA_ESPEC] + b"\n\nparrafo aniadido a posteriori\n"
        return c
    ruta = _corromper(paquete, tmp_path, ataque, "espec")
    informe, _ = _verificar(ruta)
    assert "C1" in _capas_en_fallo(informe)


def test_flotante_en_el_payload_cae_en_c1(paquete, tmp_path):
    """R-5: prohibido el punto flotante en toda la cadena probatoria."""
    def ataque(c):
        evs = B.eventos_de(c)
        evs[0]["payload"] = {"peso_kg": 1234.5, "unidad": "kg"}
        evs = B.rehacer_cadena(evs)
        c = B.poner_eventos(c, evs)
        c = B.rehacer_merkle(c, evs)
        return B.rehacer_manifiesto(c, evs)
    ruta = _corromper(paquete, tmp_path, ataque, "flotante")
    informe, _ = _verificar(ruta)
    assert "C1" in _capas_en_fallo(informe), (
        "un flotante en el payload debe invalidar el paquete: la serializacion "
        "de un float no esta garantizada entre lenguajes")


def test_evento_sin_autor_cae_en_c1(paquete, tmp_path):
    """Sin autor no hay evento (§8.1)."""
    def ataque(c):
        evs = B.eventos_de(c)
        evs[1]["autor_id"] = ""
        evs = B.rehacer_cadena(evs)
        c = B.poner_eventos(c, evs)
        c = B.rehacer_merkle(c, evs)
        return B.rehacer_manifiesto(c, evs)
    ruta = _corromper(paquete, tmp_path, ataque, "sin_autor")
    informe, _ = _verificar(ruta)
    assert "C1" in _capas_en_fallo(informe)


# =============================================================================
# Que el banco no se quede corto sin que nadie lo note
# =============================================================================

def test_el_banco_tiene_los_diez_ataques():
    """El canon exige diez (§5 de CLAUDE.md). Si alguien anade o quita, que se vea."""
    codigos = [a["codigo"] for a in B.ATAQUES]
    esperados = ["A-%02d" % i for i in range(1, 11)]
    assert codigos == esperados, (
        "el banco debe tener exactamente los diez ataques del canon, en orden. "
        "Encontrados: %s" % codigos)


def test_a06_esta_marcado_como_de_capa_4():
    """A-06 es la demostracion central y su capa esperada no debe cambiarse
    a la ligera: si alguien la baja a C3, se pierde el argumento."""
    a06 = [a for a in B.ATAQUES if a["codigo"] == "A-06"][0]
    assert a06["esperado"] == "C4"
