# A02:2025 – Security Misconfiguration

| Campo | Detalle |
|---|---|
| **Clasificación** | OWASP Top 10:2025 – A02 Security Misconfiguration (CWE-16, CWE-798, CWE-489, CWE-209) |
| **Archivos afectados** | `index.py`, `db.json` (eliminado), `.env.example`, `.gitignore` |
| **Endpoints afectados** | Toda la API (`/Registro`, `/Login`, `/Imagen`, `/Descargar`) |

## 1. Descripción de la vulnerabilidad

La aplicación estaba desplegada con una configuración insegura por defecto. Se identificaron cinco problemas:

| # | Problema | Dónde estaba | Riesgo |
|---|---|---|---|
| 1 | **Credenciales en el repositorio** | `db.json` con usuario, contraseña, puerto y nombre de la base, versionado en git | Cualquiera con acceso al repositorio o a su historial obtiene acceso a la base de datos (CWE-798) |
| 2 | **Modo debug activo** | `run(..., debug=True)` | En Bottle, el modo debug muestra trazas completas con rutas, código y variables ante cualquier error (CWE-489) |
| 3 | **Exposición de red innecesaria** | `run(host='0.0.0.0')` | El servicio escuchaba en todas las interfaces aunque Nginx ya hace de proxy hacia `127.0.0.1:8080`, por lo que se podía acceder directamente a la API sin pasar por HTTPS |
| 4 | **Errores sin control ni registro** | `print(e)` en cada `except`, `print(Path("img").resolve(), ...)` en `/Descargar` y páginas de error por defecto de Bottle | Filtra rutas y detalles internos (CWE-209) y no deja registros auditables de los incidentes |
| 5 | **Sin headers de seguridad HTTP** | Ninguna respuesta incluía cabeceras de protección | El navegador no recibe instrucciones para protegerse de sniffing, clickjacking o degradación a HTTP |

## 2. Cómo se podía explotar

- **Filtración de credenciales:** un clon del repositorio, un fork público o el historial de git bastaba para leer `db.json` y conectarse a MySQL con el usuario de la aplicación.
- **Reconocimiento por errores:** enviar un JSON mal formado o un `id` inexistente a `/Descargar` generaba una excepción. Con `debug=True` la respuesta traía el traceback con rutas del servidor y fragmentos de código.
- **Acceso directo al puerto 8080:** al escuchar en `0.0.0.0`, un atacante podía saltarse Nginx y el certificado TLS, enviando credenciales y tokens en texto plano.
- **Clickjacking y sniffing:** sin `X-Frame-Options` ni `X-Content-Type-Options`, las respuestas podían incrustarse en otro sitio o ser interpretadas con otro tipo de contenido.

## 3. Impacto

- **Confidencialidad:** acceso a la base de datos por credenciales expuestas; fuga de rutas y estructura interna.
- **Integridad:** con las credenciales se pueden modificar o borrar datos.
- **Disponibilidad:** acceso directo al puerto de la aplicación sin las protecciones del proxy.
- **Trazabilidad:** sin logs no es posible reconstruir qué ocurrió durante un ataque.

## 4. Solución aplicada

**Credenciales fuera del código.** Se eliminó `db.json` y la conexión ahora se arma con variables de entorno (`DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`). Si falta alguna obligatoria, la aplicación falla de forma explícita en lugar de usar valores por defecto. Se agregó `.env.example` como plantilla sin secretos y `.env` se incluyó en `.gitignore`.

```python
def getDatabase():
	return mysql.connector.connect(
		host=os.environ.get("DB_HOST", "localhost"),
		port=int(os.environ.get("DB_PORT", "3306")),
		database=os.environ["DB_NAME"],
		user=os.environ["DB_USER"],
		password=os.environ["DB_PASSWORD"]
	)
```

**Debug y red.** El modo debug depende de `APP_DBG` y por defecto está apagado. El host por defecto es `127.0.0.1` (configurable con `APP_HOST`), de modo que la API solo es accesible a través del proxy Nginx con TLS.

**Logging.** Se configuró `logging` con salida a `app.log` (ignorado por git) y se reemplazaron los `print(e)` por `log.exception(...)`, que guarda fecha, nivel y traza. Se eliminó el `print` que mostraba rutas en `/Descargar`.

**Errores genéricos.** Se definieron handlers para 404, 405 y 500 que devuelven un JSON con un código (`{"R": -404}`) sin trazas ni versiones.

**Headers de seguridad** en todas las respuestas mediante un hook `after_request`:

| Header | Valor | Protege contra |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | MIME sniffing |
| `X-Frame-Options` | `DENY` | Clickjacking |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` | Carga y embebido de contenido |
| `Referrer-Policy` | `no-referrer` | Fuga de URLs |
| `Cache-Control` | `no-store` | Cacheo de respuestas con tokens |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Degradación a HTTP |



## Referencias

- OWASP Top 10:2025 – A02 Security Misconfiguration
- CWE-16 Configuration, CWE-798 Hard-coded Credentials, CWE-489 Active Debug Code, CWE-209 Error Message Containing Sensitive Information