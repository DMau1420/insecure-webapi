# A01:2025 – Broken Access Control

| Campo | Detalle |
|---|---|
| **Clasificación** | OWASP Top 10:2025 – A01 Broken Access Control (CWE-639: IDOR, CWE-862: Missing Authorization, CWE-22: Path Traversal) |
| **Archivo afectado** | `index.py` |
| **Endpoints afectados** | `/Descargar`, `/Imagen` y la nueva ruta `GET /img/<nombre>` |

## 1. Descripción de la vulnerabilidad

La API no controlaba correctamente quién podía acceder a cada imagen:

| # | Problema | Código vulnerable (original) | Riesgo |
|---|---|---|---|
| 1 | **El token no se validaba** | `/Descargar` consultaba `AccesoToken` y luego reutilizaba la variable `R` para la consulta de la imagen, sin comprobar el resultado del token | Cualquier persona, incluso sin sesión, recibía la imagen (CWE-862) |
| 2 | **Sin control de propiedad e ids predecibles** | `Select name,ruta from Imagen where id = ...` con ids secuenciales | Un usuario autenticado, o no, podía pedir las imágenes de cualquier otro recorriendo los ids (IDOR, CWE-639) |
| 3 | **Archivos servidos desde la raíz del proyecto** | `static_file(R[0][1], Path(".").resolve())` | El directorio servido incluía el código y la configuración del proyecto; cualquier ruta alterada en la base de datos permitiría leerlos (CWE-22) |
| 4 | **Extensión sin validar** | `f'img/{idImagen}.{ext}'` con `ext` tomado del JSON del cliente | Permite manipular la ruta de destino y guardar archivos con extensiones arbitrarias (CWE-22) |
| 5 | **Token inválido en `/Imagen`** | `id_Usuario = R[0][0]` sin comprobar que `R` tuviera filas | Un error 500 en lugar de rechazar la petición |

## 2. Cómo se podía explotar

- **Descarga sin autenticación.** Una petición a `/Descargar` con `{"token": "x", "id": 1}` devolvía la imagen 1 aunque el token no existiera.
- **Enumeración (IDOR).** Un bucle con `id` de 1 a N descargaba las imágenes de todos los usuarios.
- **Ruta y extensión manipuladas.** Con una extensión como `png/../../x` el cliente influía en la ruta final del archivo guardado.

## 3. Impacto

- **Confidencialidad:** exposición de imágenes de todos los usuarios sin autenticarse.
- **Integridad:** escritura de archivos con nombre y extensión controlados por el atacante.
- **Disponibilidad:** errores 500 provocados con un token inexistente.

## 4. Solución aplicada

**Autenticación y propiedad en `/Descargar`.** Se valida el token y la consulta de la imagen incluye al dueño, por lo que solo se pueden pedir imágenes propias.

```python
cursor.execute('select id_Usuario from AccesoToken where token = %s', (TKN,))
R = cursor.fetchall()
if not R:
	return {"R":-2}
cursor.execute('Select ruta from Imagen where id = %s and id_Usuario = %s', (idImagen, R[0][0]))
```

**URL aleatoria.** Las imágenes se guardan con un nombre de 128 bits generado con `secrets.token_urlsafe(16)`. `/Descargar` ya no devuelve el archivo, sino su URL, que no se puede adivinar ni recorrer.

```python
nombre_archivo = f"{secrets.token_urlsafe(16)}.{ext}"
...
return {"R":0, "D": f"{PUBLIC_URL}/img/{nombre}"}
```

**Ruta restringida para servir archivos.** `GET /img/<nombre>` solo acepta nombres que coincidan con una expresión regular (sin `/` ni `..`) y sirve únicamente la carpeta `img/` con `static_file(..., root=...)`.

```python
@get(r'/img/<nombre:re:[A-Za-z0-9_-]+\.[A-Za-z0-9]+>')
def servir_imagen(nombre):
	return static_file(nombre, root=str(Path("img").resolve()))
```

**Validación en `/Imagen`.** La extensión se compara con una lista blanca (`png`, `jpg`, `jpeg`, `gif`), un token inválido responde `R = -2` y el archivo temporal usa un nombre aleatorio para evitar colisiones entre subidas.

## Consideraciones

- La URL devuelta es un **enlace no adivinable**: quien la conozca puede abrir la imagen sin token. 
- Las imágenes subidas antes de este cambio usan el nombre antiguo (`id.ext`) y deben volver a subirse.

## Referencias

- OWASP Top 10:2025 – A01 Broken Access Control
- CWE-639, CWE-862, CWE-22