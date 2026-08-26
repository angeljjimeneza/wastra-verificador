# ANEXO NORMATIVO · `wastra-export/1.1`

**Estado: borrador normativo.** Define las tres adiciones de la versión menor
`1.1` sobre la `1.0`. Una vez aprobado, su contenido se incorpora a
`ESPECIFICACION-FORMATO.md` y esta versión pasa a ser la referencia.

> **Todas las adiciones de este anexo son OPCIONALES y compatibles hacia atrás.**
> Un paquete `1.1` que no las use es idéntico a uno `1.0`. Un verificador `1.0`
> que encuentre un paquete `1.1` actúa según §17.3 de la especificación: verifica
> lo que entiende y **advierte de forma destacada**.

---

## A · `adjuntos/` — evidencias de contenido direccionable

### A.1 Por qué existe

Una fotografía del material, la lectura cruda de un sensor o un albarán escaneado
son **prueba**, y hoy quedan fuera de la cadena. Un registro que dice «se pesaron
15,2 t» y una foto sin atar son dos cosas separadas: la foto se puede sustituir y
nadie lo notaría.

**Este anexo ata el adjunto a la cadena por su huella.**

### A.2 Ubicación y nombre

```
adjuntos/<sha256>
```

- `<sha256>` es la huella SHA-256 **de los bytes del fichero**, en hexadecimal
  minúsculo de 64 caracteres, **sin extensión**.
- El nombre del fichero **es** su huella: comprobar la integridad de un adjunto es
  recalcular el SHA-256 de su contenido y compararlo con su propio nombre.
- **Contenido idéntico, un solo fichero.** Dos eventos que referencien la misma
  fotografía comparten el mismo adjunto; no se duplica.

### A.3 Referencia desde el evento

`adjuntos` es la **segunda y última clave reservada dentro de `payload`**, junto a
`corrige_evento_id`. Todo lo demás dentro de `payload` sigue siendo opaco al
verificador.

```json
"payload": {
  "lote_id": "L-2026-0001",
  "adjuntos": [
    {"sha256": "hex64", "tipo": "image/jpeg", "bytes": 184320, "rol": "fotografia_carga"}
  ]
}
```

| Clave | Tipo | Regla |
|---|---|---|
| `sha256` | cadena | hex64 minúsculo. **Obligatoria.** |
| `tipo` | cadena | Tipo de medio IANA. Obligatoria. El verificador **no** valida que el contenido corresponda al tipo declarado. |
| `bytes` | entero | Tamaño exacto en bytes. **Entero, nunca flotante.** Obligatoria. |
| `rol` | cadena | Etiqueta libre de despliegue. Opcional. |

### A.4 Qué comprueba el verificador — capa C1

1. Todo `sha256` referenciado desde un evento **existe** en `adjuntos/`.
2. El SHA-256 recalculado de cada fichero **coincide con su nombre**.
3. El tamaño real **coincide** con `bytes`.
4. **Un adjunto presente en `adjuntos/` que no referencie ningún evento es una
   advertencia**, no un fallo: puede proceder de una exportación parcial. En modo
   `--estricto` es error.

### A.5 Lo que este anexo NO prueba

**El adjunto está atado a la cadena; su contenido no está verificado.** Que una
fotografía no se haya sustituido no significa que muestre lo que dice mostrar, ni
que se tomara donde y cuando se declara. **Sigue rigiendo el principio del §1:
integridad, orden, autoría y anterioridad; nunca veracidad.**

---

## B · `modo_captura` — cómo se originó el dato

### B.1 Por qué existe, y por qué ahora

La `1.0` supone implícitamente que **una persona declara** y el sistema registra.
Cuando parte de la captación pase a instrumentos automáticos, habrá que distinguir
tres situaciones que hoy no se pueden distinguir: dato declarado por una persona,
dato capturado por un equipo, y dato en que ambos coinciden o discrepan.

> 🔴 **Se añade ahora aunque nadie lo use todavía.** Un registro anclado no se
> reescribe: si este campo se introdujera dentro de dos años, existirían **dos
> generaciones de eventos anclados** que un verificador debería tratar de forma
> distinta para siempre. **Añadirlo hoy cuesta un párrafo; añadirlo después parte
> el histórico en dos.**

### B.2 Definición

`modo_captura` es una **undécima clave OPCIONAL de nivel superior** del evento.
Su ausencia equivale a `"declarado"`, que es lo que la `1.0` supone.

| Valor | Significado |
|---|---|
| `"declarado"` | Una persona declaró el dato. `autor_id` identifica a esa persona. |
| `"capturado"` | Un instrumento capturó el dato sin intervención humana. `dispositivo_id` identifica al instrumento y `autor_id`, al responsable de su operación. |
| `"concordante"` | Persona e instrumento registraron el mismo hecho **y coinciden** dentro de la tolerancia declarada en `payload`. |
| `"discrepante"` | Persona e instrumento registraron el mismo hecho **y no coinciden**. |

**Cerrado a estos cuatro valores.** Cualquier otro es fallo de C1 en un paquete que
declare `1.1`.

### B.3 Regla dura sobre `discrepante`

> **Un evento `discrepante` es un evento válido.** El verificador lo acepta, lo
> encadena y lo ancla como cualquier otro.

**No es un error del sistema: es el sistema funcionando.** Registrar la
discrepancia y conservarla es precisamente lo que permite detectarla después. Un
formato que rechazara las discrepancias estaría borrando la única señal que
importa.

Lo que se hace con una discrepancia —abrir una no conformidad, repesar, escalar—
es materia del procedimiento operativo, **no de este formato**.

### B.4 Efecto sobre el nivel superior cerrado

La §8.1 de la `1.0` fija **exactamente diez claves**. En la `1.1` el nivel superior
admite **diez claves obligatorias y una opcional**:

- En un paquete que declare `version: "1.0"`, `modo_captura` en el nivel superior
  es **fallo de C1**.
- En un paquete que declare `version: "1.1"`, es **opcional**.
- Cualquier otra clave adicional sigue siendo fallo de C1 en ambas versiones.

**`modo_captura` entra en la serialización canónica del evento** y, por tanto, en
el cálculo de su `hash`, como cualquier otro campo de nivel superior.

### B.5 Por qué en el nivel superior y no dentro de `payload`

Podría objetarse que `payload` también entra en el hash, y es cierto: ahí también
sería inalterable. **El motivo es otro, y es el que decide.**

`payload` es **opaco para el verificador** (§8.6): no mira dentro. Si
`modo_captura` viviera ahí, **nadie comprobaría que su valor es uno de los
cuatro.** Un paquete podría declarar `"concordant"` por error de tecleo, o
`"verificado"` por invención, y pasaría la verificación sin que nadie lo notase.

En el nivel superior el valor está **acotado y es comprobable**, y además el
verificador puede **contarlo y decirlo en el informe**. Un campo que nadie
valida y nadie informa no es un campo normativo: es una nota.

---

## C · `cadena_id` — cadenas por origen

*Reservado. Se especifica cuando se cierre el modelo de evento de Zona 0.*

La `1.0` define **una sola cadena global** (§9). Cuando varios orígenes registren
en paralelo y sin conectividad continua, una cadena única obliga a un ordenamiento
central que en campo no siempre existe.

**Nada de lo que se defina aquí debe alterar la comprobación de un paquete `1.0`.**

---

## D · Compatibilidad · resumen

| Situación | Comportamiento |
|---|---|
| Verificador `1.1` lee paquete `1.0` | Verifica con normalidad. `modo_captura` ausente = `"declarado"` |
| Verificador `1.0` lee paquete `1.1` **sin** adjuntos ni `modo_captura` | Verificación completa y correcta |
| Verificador `1.0` lee paquete `1.1` **con** las adiciones | Verifica cadena, Merkle y anclaje; **advierte de forma destacada** de que no comprueba los adjuntos ni el modo de captura. En `--estricto`, error |
| Cualquier verificador lee versión mayor distinta | **Rechaza** (código 2). No adivina |

---

## E · Estado · implementado el 23-08-2026

| | Qué | Estado |
|---|---|---|
| 1 | Comprobación de `adjuntos/` en `verificar.py` | 🟢 ya estaba |
| 2 | Comprobación de **`modo_captura`** en `verificar.py` | 🟢 **hecho** |
| 3 | Recuento por modo en el informe de texto y en el JSON | 🟢 **hecho** |
| 4 | **A-11** sustituir un adjunto conservando el nombre | 🟢 **hecho** — cae en C1 |
| 5 | **A-12** ocultar una discrepancia | 🟢 **hecho** — cae en C2 |
| 6 | Pruebas: 4 modos válidos, valor inválido, `1.0` con la undécima, ausencia = `declarado`, discrepante no falla | 🟢 **hecho** — 42 pruebas en verde |
| 7 | El generador de ejemplo produce 1 `concordante` y 1 `discrepante` | 🟢 **hecho** |
| 8 | Incorporar A y B a `ESPECIFICACION-FORMATO.md` §6 y §8 | 🔴 **pendiente** |
| 9 | Vectores de prueba en §18 de la especificación | 🔴 pendiente |
| 10 | Cerrar C, `cadena_id`, con el modelo de Zona 0 | ⚪ pendiente |

> ⚠️ **Sobre el punto 8.** La especificación viaja **dentro** de cada paquete y su
> huella se declara en el manifiesto (`especificacion_sha256`). Al incorporarla,
> esa huella cambia y **hay que regenerar el paquete de ejemplo** — lo que borra
> las anclas ya confirmadas en Bitcoin. Por eso no lo he hecho todavía: conviene
> hacerlo **de una sola vez**, cuando también esté cerrado `cadena_id`, y volver
> a anclar una única vez.

---

## F · Corrección a la primera redacción de este anexo

La primera versión describía **A-12** como *«declarar `concordante` con valores
que no concuerdan»*. **Al implementarlo se vio que ese ataque no es detectable, y
que no debe serlo.**

El verificador **no mira dentro de `payload`** y, por tanto, no puede saber qué
valores concordaban ni con qué tolerancia. Pedirle que lo juzgue sería romper el
principio del §8.6 y convertirlo en un árbitro de contenido — justo lo que este
proyecto sostiene que no debe ser.

**El ataque real, y el que sí importa, es otro:** alguien que **cambia
`discrepante` por `concordante`** para que nadie abra una no conformidad. Ése es
el fraude verosímil, y **cae en C2** porque el campo está en el hash. Si el
atacante recalcula la cadena, cae en C3; si recalcula también las raíces, cae en
C4. El mismo camino de A-05 y A-06, aplicado al campo que dice si hubo
desacuerdo.

> Que el ataque cambiara al implementarlo es una señal buena, no mala: **escribir
> el código obligó a distinguir entre lo que el verificador puede probar y lo que
> solo podría opinar.**
