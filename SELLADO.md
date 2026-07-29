# SELLADO.md · sello de `ESPECIFICACION-FORMATO.md`

> Este documento gobierna el **sellado** de la especificación del formato.
> Sellar es fijar la huella SHA-256 de `ESPECIFICACION-FORMATO.md` como
> constante en el verificador y anclarla en el tiempo. A partir de ese momento
> la especificación es **inmutable**: la comprobación a tres bandas (§16.1 de la
> especificación) rechazaría cualquier paquete emitido bajo una copia distinta.

---

## ESTADO ACTUAL

```
estado: BORRADOR — NO SELLADO
huella_sellada:
version_sellada:
anclaje_ots:
fecha_sellado:
```

El campo `huella_sellada` está **vacío a propósito**. Mientras lo esté, la
especificación es un borrador editable y el repositorio no exige ningún sello
(lo hace cumplir `tests/test_huella_especificacion.py`).

---

## POR QUÉ NO SE SELLA TODAVÍA

En el momento en que la huella de `ESPECIFICACION-FORMATO.md` quede compilada en
el verificador, el documento se vuelve **inmutable**: cualquier cambio posterior
invalidaría la comprobación a tres bandas de **todos los paquetes ya emitidos**.
Corregir la especificación dejaría de ser *editar* y pasaría a ser *publicar una
versión nueva*. La especificación se convierte así en el **primer objeto
gobernado por sus propias reglas**.

Por eso **no se sella una especificación que ninguna implementación ha
validado**. Hacerlo contradiría la **Decisión 0** de `DECISIONES-FORMATO.md`
(*«no se especifica lo que no se ha validado»*): un sello sobre reglas no
probadas congela posibles errores y los convierte en deuda permanente.

---

## CONDICIÓN PARA SELLAR (requisito)

Se sella **solo cuando se cumpla, de forma demostrable, todo lo siguiente**:

1. El **verificador** implementa las capas **C1, C2 y C3** y las supera sobre un
   **paquete real** generado por `generar_ejemplo.py`.
2. El **banco de ataques** (`banco_de_ataques.py`) está **en verde**: los diez
   ataques se detectan en la capa que les corresponde.
3. Ambas cosas se ejecutan sobre el mismo paquete real, no sobre datos de
   juguete distintos de los que se distribuirán.

Hasta que este requisito se cumpla y se verifique, `huella_sellada` permanece
vacío.

---

## REGLA POSTERIOR AL SELLADO

Una vez sellada, **cualquier cambio en `ESPECIFICACION-FORMATO.md` exige un
incremento de versión del formato** (§17 de la especificación) y un **nuevo
sello**. **Nunca** una edición silenciosa: editar el fichero sellado sin
cambiar la versión rompería la comprobación a tres bandas de los paquetes ya
emitidos sin dejar rastro en el número de versión, que es precisamente el
engaño que este mecanismo existe para impedir.

---

## QUÉ SE HARÁ AL SELLAR (procedimiento)

Cuando se cumpla la condición:

1. **Calcular** el SHA-256 de los bytes UTF-8 de `ESPECIFICACION-FORMATO.md`.
2. **Escribirlo** en `huella_sellada` de este documento, junto con
   `version_sellada` (p. ej. `1.0`) y `fecha_sellado`.
3. **Anclarlo** con OpenTimestamps: generar la prueba `.ots` sobre los 32 bytes
   binarios de esa huella y registrar la referencia en `anclaje_ots`.
4. **Fijarlo como constante** en el verificador: la huella deja de leerse de
   este fichero y pasa a estar **compilada** en el código, para que la tercera
   banda de la comprobación (§16.1) sea la que el verificador *ya conoce* y no
   una que el entorno pueda cambiar.

---

## ESTADO DE TRANSICIÓN (mientras `huella_sellada` esté vacío)

- `generar_ejemplo.py` calcula `especificacion_sha256` **dinámicamente** a
  partir de la copia que incrusta en el paquete.
- El verificador lee la huella esperada **de este fichero (`SELLADO.md`)** en
  lugar de tenerla compilada.
- Ambos puntos llevarán un comentario `TODO: SELLADO` marcando exactamente
  dónde cambia el comportamiento en el momento de sellar (paso 4 del
  procedimiento). Esos ficheros aún no existen; el TODO se añadirá al crearlos.

---

*© 2026 Angel José Jiménez Álvarez · Documento de gobernanza del repositorio
`wastra-verificador`. Licencia Apache-2.0.*
