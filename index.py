import os
import json
import random
import hashlib
import logging
import mysql.connector
import base64
import logging
import shutil
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from bottle import get, route, run, template, post, request, response, static_file, error, hook

# Logging: se guarda en un archivo, sin mostrar detalles al cliente
logging.basicConfig(
	filename=os.environ.get("LOG_FILE", "app.log"),
	level=logging.INFO,
	format="%(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger("api")

# Subida de archivos
MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB
EXT_PERMITIDAS = {"png", "jpg", "jpeg", "gif"}


@contextmanager
def get_db_connection():
	"""Abre la conexion y garantiza que siempre se cierre."""
	db = mysql.connector.connect(
		host = os.environ.get("DB_HOST", "localhost"),
		port = int(os.environ.get("DB_PORT", 3306)),
		database = os.environ.get("DB_NAME", "webapps"),
		user = os.environ.get("DB_USER", "udbwebaps"),
		password = os.environ.get("DB_PASSWORD", "")
	)
	try:
		yield db
	finally:
		db.close()


# Cabeceras de seguridad en todas las respuestas
@hook('after_request')
def security_headers():
	response.set_header('X-Content-Type-Options', 'nosniff')
	response.set_header('X-Frame-Options', 'DENY')
	response.set_header('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'")
	response.set_header('Referrer-Policy', 'no-referrer')
	response.set_header('Cache-Control', 'no-store')
	response.set_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')


# Errores genericos (sin stack traces)
@error(404)
def error404(e):
	response.content_type = 'application/json'
	return json.dumps({"R": -404})

@error(500)
def error500(e):
	log.error("Error 500: %s", e.exception, exc_info=True)
	response.content_type = 'application/json'
	return json.dumps({"R": -500})


def getToken():
	tiempo = datetime.now().timestamp()
	numero = random.random()
	cadena = str(tiempo) + str(numero)
	numero2 = random.random()
	cadena2 = str(numero)+str(tiempo)+str(numero2)
	m = hashlib.sha1()
	m.update(cadena.encode())
	P = m.hexdigest()
	m = hashlib.md5()
	m.update(cadena.encode())
	Q = m.hexdigest()
	return f"{P[:20]}{Q[20:]}"

"""
/*
 * Registro recibe un JSON con el siguiente formato
 *
 * :
 *		"uname": "XXX",
 *		"email": "XXX",
 * 		"password": "XXX"
 *
 * */
"""
@post('/Registro')
def Registro():
	# obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	R = 'uname' in request.json and 'email' in request.json and 'password' in request.json
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}
	# TODO validar correo en json
	try:
		with get_db_connection() as db:
			with db.cursor() as cursor:
				cursor.execute('insert into Usuario values (Null, %s, %s, MD5(%s))', (request.json["uname"], request.json["email"], request.json["password"]))
				R = cursor.lastrowid
				db.commit()
	except Exception:
		log.exception("Error en Registro")
		return {"R":-2}
	return {"R":0,"D":R}


"""
/*
 * Login recibe un JSON con el siguiente formato
 *
 * :
 *		"uname": "XXX",
 * 		"password": "XXX"
 *
 *
 * Debe retornar un Token
 * */
"""

@post('/Login')
def Login():
	if not request.json:
		return {"R":-1}
	R = 'uname' in request.json  and 'password' in request.json
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}

	try:
		with get_db_connection() as db:
			with db.cursor() as cursor:
				cursor.execute('Select id from  Usuario where uname = %s and password = md5(%s)', (request.json["uname"], request.json["password"]))
				R = cursor.fetchall()
			if not R:
				return {"R":-3}

			T = getToken()
			try:
				with db.cursor() as cursor:
					cursor.execute('Delete from AccesoToken where id_Usuario = %s', (R[0][0],))
					cursor.execute('insert into AccesoToken values(%s, %s, now())', (R[0][0], T))
					db.commit()
				return {"R":0,"D":T}
			except Exception:
				log.exception("Error guardando token")
				return {"R":-4}
	except Exception:
		log.exception("Error en Login")
		return {"R":-2}


"""
/*
 * Subir imagen recibe un JSON con el siguiente formato
 *
 *
 * 		"token: "XXX"
 *		"name": "XXX",
 * 		"data": "XXX",
 * 		"ext": "PNG"
 *
 *
 * Debe retornar codigo de estado
 * */
"""
@post('/Imagen')
def Imagen():
	# Directorio
	Path('tmp').mkdir(exist_ok=True)
	Path('img').mkdir(exist_ok=True)

	if not request.json:
		return {"R":-1}
	R = 'name' in request.json  and 'data' in request.json and 'ext' in request.json  and 'token' in request.json
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}

	# Validar extension (lista blanca) y tamano
	ext = str(request.json['ext']).lower()
	if ext not in EXT_PERMITIDAS:
		return {"R":-1}
	if len(str(request.json['data'])) > MAX_UPLOAD_BYTES * 4 // 3 + 4:
		return {"R":-1}
	try:
		contenido = base64.b64decode(str(request.json['data']).encode(), validate=True)
	except Exception:
		return {"R":-1}
	if len(contenido) > MAX_UPLOAD_BYTES:
		return {"R":-1}

	TKN = request.json['token']

	try:
		with get_db_connection() as db:
			# Validar si el usuario esta en la base de datos
			with db.cursor() as cursor:
				cursor.execute('select id_Usuario from AccesoToken where token = %s', (str(TKN),))
				R = cursor.fetchall()
			if not R:
				return {"R":-2}
			id_Usuario = R[0][0]

			tmp_path = f'tmp/{id_Usuario}'
			with open(tmp_path, "wb") as imagen:
				imagen.write(contenido)

			# Guardar info del archivo en la base de datos
			try:
				with db.cursor() as cursor:
					cursor.execute('insert into Imagen values(null, %s, %s, %s)', (str(request.json["name"]), "img/", id_Usuario))
					cursor.execute('select max(id) as idImagen from Imagen where id_Usuario = %s', (id_Usuario,))
					R = cursor.fetchall()
					idImagen = R[0][0]
					cursor.execute('update Imagen set ruta = %s where id = %s', (f'img/{idImagen}.{ext}', idImagen))
					db.commit()
				# Mover archivo a su nueva locacion
				shutil.move(tmp_path, f'img/{idImagen}.{ext}')
				return {"R":0,"D":idImagen}
			except Exception:
				log.exception("Error guardando imagen")
				return {"R":-3}
	except Exception:
		log.exception("Error en Imagen")
		return {"R":-2}


"""
/*
 * Descargar recibe un JSON con el siguiente formato
 *
 * :
 * 		"token: "XXX",
 * 		"id": "XXX"
 *
 *
 * Debe retornar la imagen
 * */
"""

@post('/Descargar')
def Descargar():
	if not request.json:
		return {"R":-1}
	R = 'token' in request.json and 'id' in request.json
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}

	TKN = request.json['token']
	idImagen = request.json['id']

	try:
		with get_db_connection() as db:
			# Comprobar que el usuario sea valido
			with db.cursor() as cursor:
				cursor.execute('select id_Usuario from AccesoToken where token = %s', (str(TKN),))
				R = cursor.fetchall()
			if not R:
				return {"R":-2}

			# Buscar imagen y enviarla
			with db.cursor() as cursor:
				cursor.execute('Select name,ruta from  Imagen where id = %s', (idImagen,))
				R = cursor.fetchall()
	except Exception:
		log.exception("Error en Descargar")
		return {"R":-3}

	if not R:
		return {"R":-3}

	nombre_archivo = os.path.basename(R[0][1])
	return static_file(nombre_archivo, root=str(Path("img").resolve()))


dbg_mode = os.environ.get("APP_DBG", "false").lower() == "true"

if __name__ == '__main__':
    run(host='0.0.0.0', port=8080, debug=dbg_mode)
