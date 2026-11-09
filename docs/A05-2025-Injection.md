# A05:2025 – Injection (SQL Injection)

| Campo | Detalle |
|---|---|
| **Clasificación** | OWASP Top 10:2025 – A05 Injection (CWE-89: SQL Injection) |
| **Archivo afectado** | `index.py` |
| **Endpoints afectados** | `/Registro`, `/Login`, `/Imagen`, `/Descargar` |

## 1. Descripción de la vulnerabilidad

La API construía las consultas SQL **concatenando directamente los datos que envía el cliente** (campos del JSON del request y el token) dentro de cadenas de texto, mediante f-strings y concatenación con `+`. El motor de MySQL recibe una sola cadena y no puede distinguir entre la estructura de la consulta y los datos. Por eso, un atacante que incluya comillas y sintaxis SQL en un campo puede **cerrar el valor esperado y agregar su propia lógica** a la consulta.

Este es el patrón clásico de inyección SQL y aparecía en prácticamente todos los endpoints:

| Endpoint | Código vulnerable (original) | Dato no confiable |
|---|---|---|
| `/Registro` | `insert into Usuario values(null,"{uname}","{email}",md5("{password}"))` | `uname`, `email`, `password` |
| `/Login` | `Select id from Usuario where uname ="{uname}" and password = md5("{password}")` | `uname`, `password` |
| `/Login` | `Delete from AccesoToken where id_Usuario = "{id}"` e `insert into AccesoToken ...` | valores derivados de la consulta anterior |
| `/Imagen` | `select id_Usuario from AccesoToken where token = "{TKN}"` | `TKN` (token) |
| `/Imagen` | `insert into Imagen values(null,"{name}","img/",{id_Usuario})` | `name` |
| `/Imagen` | `update Imagen set ruta = "img/{idImagen}.{ext}" where id = {idImagen}` | `ext` |
| `/Descargar` | `select id_Usuario from AccesoToken where token = "'+TKN+'"` | `TKN` |
| `/Descargar` | `Select name,ruta from Imagen where id = '+str(idImagen)` | `idImagen` |

Además, el endpoint `/Login` escribía en `/tmp/log` las sentencias SQL completas (incluyendo datos del usuario y el token generado), lo que dejaba información sensible en un archivo de texto plano.

## 2. Cómo se podía explotar

**Bypass de autenticación en `/Login`.** Con el body:

```json
{"uname": "admin\" -- ", "password": "cualquiera"}
```

la consulta resultante queda:

```sql
Select id from Usuario where uname ="admin" -- " and password = md5("cualquiera")
```

El `-- ` convierte en comentario el resto de la línea, se elimina la condición de contraseña y la API entrega un token válido del usuario `admin`.

**Inyección en `/Registro`.** Un `uname` con comillas permite cerrar el valor y manipular las columnas del `insert`, o provocar errores que revelan la estructura de la tabla.

**Inyección en `/Descargar` e `/Imagen`.** El token y el `id` se concatenaban sin validación, por lo que se podían usar sentencias como `UNION SELECT` para extraer datos de otras tablas (por ejemplo, tokens de otros usuarios) o alterar registros.

## 3. Impacto

- **Confidencialidad:** lectura de usuarios, correos, hashes de contraseña, tokens y rutas de archivos.
- **Integridad:** modificación o eliminación de tokens, imágenes y usuarios.
- **Autenticación:** inicio de sesión como cualquier usuario sin conocer su contraseña.
- **Robo de sesión:** al poder obtener tokens válidos de otros usuarios.
- **Disponibilidad:** posibilidad de borrar o corromper datos.

## 4. Solución aplicada

Se reemplazaron todas las consultas por **consultas parametrizadas** del conector de MySQL. En lugar de insertar los valores dentro del texto SQL, se usan marcadores `%s` y los valores se pasan por separado como segundo argumento de `cursor.execute(sql, valores)`. El conector se encarga de escapar los valores y de mantenerlos separados de la estructura de la consulta, de modo que **lo que escriba el usuario siempre se interpreta como dato y nunca como código SQL**.

Ejemplo (`/Login`):

```python
# Antes
cursor.execute(f'Select id from Usuario where uname ="{request.json["uname"]}" and password = md5("{request.json["password"]}")')

# Después
sql = 'Select id from Usuario where uname = %s and password = md5(%s)'
values = (request.json["uname"], request.json["password"])
cursor.execute(sql, values)
```

Consultas parametrizadas en este commit:

- `/Registro`: `insert` de usuario.
- `/Login`: `select` de usuario, `delete` e `insert` en `AccesoToken`.
- `/Imagen`: `select` del token, `insert` de la imagen, `select max(id)` y `update` de la ruta.
- `/Descargar`: `select` del token y `select` de la imagen.


## Referencias

- OWASP Top 10:2025 – A05 Injection
