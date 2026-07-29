# DECISIONES-FORMATO.md · `wastra-export/1.0`

> **Documento normativo.** Resuelve las veinte ambigüedades detectadas en la sección 3 de `CLAUDE.md`.
> Ante conflicto entre este documento y cualquier otro del repositorio, **prevalece este**.
> Decisiones adoptadas por **Angel José Jiménez Álvarez**, titular, el 29 de julio de 2026.
> Nodo de grafo: `DOC·TEC·GOB·FOR·DEC·G2·AJJ·MUL·N0030`
> Copia en bóveda: `01-PROYECTOS/HITO/05-DESARROLLO/HIT-B0-C01-D1_Decisiones_Formato.md`

---

## DECISIÓN TRANSVERSAL 0 · ALCANCE DE LA VERSIÓN 1.0

**La versión 1.0 del formato admite exclusivamente exportaciones COMPLETAS.** Toda exportación cubre un rango continuo de secuencias sin omisiones.

La exportación **parcial o confidencial** —revelar la existencia de un evento sin revelar su contenido— es una capacidad real y valiosa, pero **queda reservada para la versión 1.1**, con diseño propio. No se especifica lo que no se ha validado.

Consecuencias inmediatas: el campo `hojas` pasa de opcional a **obligatorio**; las preguntas 13 y 14 quedan resueltas por esta vía; y el verificador de v1.0 no necesita lógica de omisión.

**Fundamento:** el recorte de alcance aceptado para F2 se aplica también al formato. Una especificación que contempla casos que nadie ha implementado ni probado es una especificación con superficie no verificada — y este documento existe precisamente para que no la haya.

---

## A · REPRODUCIBILIDAD DE LA HUELLA

### A.1 — Canonicalización de `payload`: recursiva y sin excepción
**SÍ.** Las reglas de canonicalización se aplican **a todo el objeto evento, a cualquier profundidad de anidamiento**, `payload` incluido: claves ordenadas, separadores sin espacio, UTF-8 sin BOM y **prohibición absoluta de coma flotante en cualquier nivel**.

Un `float` a cualquier profundidad invalida el evento y hace fallar la capa C1.

### A.2 — Hojas del Merkle: **32 bytes binarios**
Las hojas `d_i` son los **32 bytes binarios** resultantes de decodificar el hexadecimal del `hash` del evento. **No** los 64 caracteres ASCII.

Es lo que establece RFC 6962 y es la única forma de que un verificador escrito en otro lenguaje reproduzca el mismo árbol.

### A.3 — Regla general: **hex en documentos, bytes en cómputo**
En todo fichero JSON, las huellas se escriben en **hexadecimal minúsculo de 64 caracteres**, incluida `raiz`. En todo cálculo criptográfico —hojas, nodos, anclaje— se opera sobre los **bytes binarios**.

Esta regla debe figurar destacada en la especificación: es la fuente más probable de error de interoperabilidad.

### A.4 — `manifiesto.json` y `merkle/*.json`: canónicos, **y no fiables**

Son JSON canónico `wastra-json-canonico/1.0`, UTF-8 sin BOM.

Y una decisión de diseño que debe quedar escrita como principio:

> **El manifiesto no se firma: se comprueba. Ninguna afirmación del manifiesto se acepta como cierta; todas se verifican contra el contenido real del paquete.**

Si `num_eventos` declara 128 y `eventos.jsonl` contiene 127, es **fallo de C1**. Si `dias` declara un día que no existe en `merkle/`, es fallo de C1. Si `rango` no coincide con las secuencias presentes, es fallo de C1.

**Fundamento:** añadir otra capa de firma sobre el manifiesto sería complejidad sin ganancia. Un manifiesto que se verifica contra el contenido no necesita ser firmado — y el principio *"no confíe, verifique"* se aplica así también al propio metadato del paquete. Es coherencia interna, no ahorro.

---

## B · EVENTOS Y CADENA

### B.5 — 🔴 La cadena de huellas es **GLOBAL**, no por paquete

**Decisión: global.** La cadena atraviesa todas las exportaciones y llega hasta el primer evento de la historia de la instalación.

**Fundamento — es la decisión más importante de este documento.** Una cadena que se reiniciara en cada paquete sería internamente coherente **con independencia de lo que hubiera ocurrido antes**. Cualquiera podría exportar los últimos cien eventos, omitir los mil anteriores, y el paquete verificaría perfectamente. El truncamiento de la historia dejaría de ser detectable, y con él desaparecería la propiedad central del sistema.

**Consecuencia obligatoria — nuevo bloque en `manifiesto.json`:**

```json
"cadena": {
  "secuencia_desde": 1041,
  "secuencia_hasta": 1168,
  "hash_anterior_esperado": "hex64",
  "hash_ultimo": "hex64"
}
```

- `hash_anterior_esperado` es el `hash` del evento inmediatamente anterior al primero del paquete. El verificador comprueba que el `hash_anterior` del primer evento coincide con este valor.
- Cuando el paquete arranca en `secuencia = 1`, ambos valen 64 ceros.
- `hash_ultimo` es el `hash` del último evento del paquete, y sirve de punto de enganche verificable para el paquete siguiente.

Así, **dos paquetes consecutivos se encadenan entre sí** y la historia completa es reconstruible y verificable sin confiar en nadie.

### B.6 — `secuencia`: **global**, estrictamente creciente, sin huecos en el rango
Numeración única en toda la historia de la instalación. `secuencia = 1` solo en el primerísimo evento. Un paquete parcial empieza en el número que le corresponde en la historia.

En v1.0 **no se admiten huecos** dentro del rango declarado: cualquier salto es fallo de C2.

### B.7 — `id`: **UUID versión 4, canónico, en minúsculas**
Formato `xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx`. El validador de C1 lo comprueba con expresión regular.

**Fundamento operativo, no estético:** los terminales generan eventos **sin cobertura**. Un identificador que exigiera coordinación con el servidor —un contador, una reserva de rango— es imposible en campo. UUID v4 permite que un teléfono en un CDT sin red cree identificadores únicos sin hablar con nadie. La elección del identificador viene impuesta por el requisito de trabajo desconectado.

### B.8 — El día de anclaje lo determina **`ts_servidor` en UTC**

**Decisión: `ts_servidor`.** Un evento capturado sin cobertura el día 1 y sincronizado el día 5 se ancla en el día 5.

**Fundamento:** es el único reloj que el sistema controla. El del dispositivo puede estar mal, ajustado o manipulado. Y el anclaje debe constatar lo que efectivamente ocurrió: **el sistema recibió este evento en este momento**.

**Obligación de honestidad — debe figurar textualmente en la especificación:**

> *El anclaje acredita el momento en que el registro recibió la declaración, no el momento en que ocurrió el hecho declarado. La marca de tiempo del dispositivo se conserva íntegra y el desfase entre ambas es visible en la exportación.*

Esa frase evita la sobreafirmación más peligrosa del sistema. Un evaluador que la lea sabrá que quien la escribió entiende lo que hizo.

### B.9 — Validación de `payload`: **opción (a)**, el verificador no mira dentro

El verificador valida **únicamente los campos comunes**. No inspecciona el interior de `payload`, con **una sola excepción**: los eventos de tipo `CORRECCION` deben contener `corrige_evento_id`.

**Fundamento — es una decisión de arquitectura, no de comodidad.** Un verificador que validara reglas de negocio quedaría **acoplado a la plataforma**: cada vez que cambiara un campo operativo habría que actualizar el verificador, y un verificador que depende de las actualizaciones del fabricante **ha dejado de ser independiente**. Y la independencia es exactamente lo que le da valor probatorio.

Frontera nítida: **el verificador comprueba integridad; la conciliación comprueba coherencia.** La conciliación —que el peso de salida cuadre con el de entrada, que el manifiesto case con la recepción— es una herramienta distinta, opcional y posterior (`conciliar.py`). No se mezclan.

### B.10 — `CORRECCION`
- **Puede** referenciar un evento de un día anterior dentro del mismo paquete: **sí**.
- **Puede** referenciar un evento ausente del paquete: si su secuencia es anterior al inicio del rango, el verificador emite **advertencia** (*referencia externa no verificable en este paquete*), no error. Si el paquete arranca en `secuencia = 1` y aun así no se encuentra, es **error de C1**.
- **Una `CORRECCION` puede ser corregida por otra**, sin límite de profundidad.

**Fundamento de lo último:** prohibir corregir una corrección obligaría a editarla, y editar viola el invariante I-1. Las correcciones encadenadas son la única forma coherente de rectificar dentro de un registro solo-anexar.

### B.11 — `autor_id` y `dispositivo_id`: cadena no vacía, sin patrón impuesto
Validación: no vacía, máximo 128 caracteres, sin caracteres de control. **No se impone patrón** — hacerlo ataría el formato a la nomenclatura de un despliegue concreto y rompería la interoperabilidad con el siguiente.

**Y sí, su lectura es correcta y debe escribirse tal cual en la especificación:**

> *Sin firma criptográfica del terminal, la autoría es una **declaración de la plataforma, no repudiable a posteriori**, no una prueba criptográfica de identidad. La firma por dispositivo con par de claves propio queda prevista para la versión 2.0.*

**Añada a la especificación una sección titulada «Límites declarados»** que recoja explícitamente lo que este formato **no** prueba: no prueba la veracidad del contenido; no prueba la identidad criptográfica del autor; no prueba el momento del hecho, solo el de su recepción.

Declarar los límites es lo que hace creíble todo lo demás. Un formato que declara lo que no puede hacer se gana el derecho a que se le crea en lo que sí.

---

## C · ÁRBOL DE MERKLE Y PAQUETE

### C.12 — Días vacíos: **no existen**
Un día sin eventos no genera fichero `merkle/`, no genera ancla y **no figura en `dias`**. Anclar un árbol vacío cuesta y no prueba nada.

### C.13 y C.14 — Resueltas por la Decisión 0
`hojas` es **obligatorio**. Las `pruebas` deben cubrir **exactamente** los eventos presentes en `eventos.jsonl` de ese día: ni uno más, ni uno menos. Una prueba de un evento ausente es **error de C1** en v1.0.

### C.15 — `dias`: exactamente los días con eventos, en orden ascendente. **No se exige contigüidad.**

**Y aquí está la clave que resuelve el ataque A-08:** la continuidad de la historia **no la garantizan las fechas, la garantiza la `secuencia`**. Un fin de semana sin operaciones deja un hueco legítimo en el calendario; un evento suprimido deja un hueco ilegítimo en la secuencia. El verificador vigila la secuencia, no el calendario.

### C.16 — `num_eventos`: total **del paquete**, y el verificador lo comprueba contando.

### C.17 — ZIP: cualquiera legible, **con dos condiciones de seguridad**

Se acepta cualquier método de compresión. Las huellas se calculan sobre los **bytes descomprimidos** de cada entrada. Ficheros inesperados dentro del ZIP: **advertencia** en modo normal, **error** en modo `--estricto`.

**Y dos requisitos de seguridad que no estaban en su lista y son obligatorios:**

1. **Rechazar toda entrada con ruta absoluta o que contenga `..`** (ataque *zip-slip*). El verificador nunca escribe fuera de su directorio temporal.
2. **Límite de descompresión** (número de entradas y tamaño total descomprimido) para impedir una bomba de descompresión.

**Fundamento:** este verificador está diseñado para que **terceros lo ejecuten sobre ficheros que nosotros no controlamos**. Un auditor puede recibir un paquete de cualquier procedencia. La herramienta debe ser segura de ejecutar sobre un paquete hostil, no solo sobre uno propio. Una herramienta de auditoría que puede ser usada como vector de ataque destruiría el proyecto entero el día que ocurriera.

---

## D · MARCAS DE TIEMPO

### D.18 — Formato estricto: **se rechaza** lo que no cumpla
`AAAA-MM-DDTHH:MM:SS.mmmZ`, exactamente tres decimales, sufijo `Z` obligatorio. No se normaliza nada: **normalizar es introducir ambigüedad, y la ambigüedad rompe la reproducibilidad**. Formato incorrecto → error de C1.

### D.19 — `ts_servidor` anterior a `ts_dispositivo`: **advertencia, no error**
Es un caso legítimo (reloj del terminal adelantado). Se registra, se informa y **se muestra el desfase en el informe**. En modo `--estricto` pasa a error.

**Fundamento:** ocultar la anomalía sería contrario al principio del sistema. **El desfase es un dato, no un defecto.** Lo que un registro honesto hace con una anomalía es enseñarla.

### D.20 — Nombre de fichero `AAAA-MM-DD`
Con ceros a la izquierda, siempre. Derivado del `ts_servidor` en **UTC estricto**, conforme a la decisión B.8. Nunca hora local.

---

## RESUMEN DE CAMBIOS SOBRE LA SECCIÓN 3 DE `CLAUDE.md`

1. **Nuevo bloque `cadena`** en `manifiesto.json` (B.5) — el cambio de mayor calado.
2. `hojas` pasa de opcional a **obligatorio** (Decisión 0).
3. Nueva sección **«Límites declarados»** en la especificación (B.11).
4. Nueva sección **«Requisitos de seguridad del verificador»**: zip-slip y bomba de descompresión (C.17).
5. `id` fijado a **UUID v4**; formato de fecha **estricto**; el día lo fija **`ts_servidor` UTC**.
6. Principio explícito: **el manifiesto no se firma, se comprueba** (A.4).
7. Frontera explícita: **verificación ≠ conciliación** (B.9).

---

*© 2026 Angel José Jiménez Álvarez · Titular de la marca Bimeth · Todos los derechos reservados.*
*Documento normativo del repositorio `wastra-verificador`. Licencia Apache-2.0 junto con el resto del repositorio.*
