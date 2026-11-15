import os
import json
import random
import hashlib
import logging
import mysql.connector
import base64
import shutil
from datetime import datetime
from pathlib import Path
from bottle import route, run, template, post, request, response, static_file, error, hook
from dotenv import load_dotenv

# Cargar las varaibles de entorno
load_dotenv(Path(__file__).resolve().parent / ".env")


logging.basicConfig(
	filename=os.environ.get("LOG_FILE", "app.log"),
	level=logging.INFO,
	format="%(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger("api")


def getDatabase():
	"""Conexion con credenciales tomadas del entorno (.env), no del repositorio."""
	return mysql.connector.connect(
		host=os.environ.get("DB_HOST", "localhost"),
		port=int(os.environ.get("DB_PORT", "3306")),
		database=os.environ["DB_NAME"],
		user=os.environ["DB_USER"],
		password=os.environ["DB_PASSWORD"]
	)

@hook('after_request')
def security_headers():
	response.set_header('X-Content-Type-Options', 'nosniff')
	response.set_header('X-Frame-Options', 'DENY')
	response.set_header('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'")
	response.set_header('Referrer-Policy', 'no-referrer')
	response.set_header('Cache-Control', 'no-store')
	response.set_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')

# Errores genericos
@error(404)
def error404(e):
	response.content_type = 'application/json'
	return json.dumps({"R": -404})

@error(405)
def error405(e):
	response.content_type = 'application/json'
	return json.dumps({"R": -405})

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
*/ 
# Registro
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 *		"uname": "XXX",
 *		"email": "XXX",
 * 		"password": "XXX"
 * 
 * */
"""

@route('/')
def index_meme():
        return static_file('meme.png',root='static')


@post('/Registro')
def Registro():

	db = getDatabase()

	if not request.json:
		return {"R":-1}
	R = 'uname' in request.json and 'email' in request.json and 'password' in request.json
	
	if not R:
		return {"R":-1}
	R = False

	try:
		with db.cursor() as cursor:
			sql = f'insert into Usuario values (Null, %s, %s, MD5(%s))'
			values = (request.json["uname"], request.json["email"], request.json["password"]);
			cursor.execute(sql, values)
			
			R = cursor.lastrowid
			db.commit()
		db.close()
	except Exception:
		log.exception("Error en Registro")
		return {"R":-2}
	return {"R":0,"D":R}

"""
/*
 * Este Registro recibe un JSON con el siguiente formato
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
	db = getDatabase()

	if not request.json:
		return {"R":-1}
	R = 'uname' in request.json  and 'password' in request.json

	if not R:
		return {"R":-1}
	R = False

	try:
		with db.cursor() as cursor:
			sql = f'Select id from  Usuario where uname = %s and password = md5(%s)'
			values = (request.json["uname"], request.json["password"])
			cursor.execute(sql, values)
			R = cursor.fetchall()
	except Exception:
		log.exception("Error en Login")
		db.close()
		return {"R":-2}
	
	if not R:
		db.close()
		return {"R":-3}
	
	T = getToken();
	try:
		with db.cursor() as cursor:
			cursor.execute('Delete from AccesoToken where id_Usuario = %s', (R[0][0],))
			cursor.execute('insert into AccesoToken values(%s, %s, now())', (R[0][0], T))
			db.commit()
			db.close()
			return {"R":0,"D":T}
	except Exception:
		log.exception("Error guardando token")
		db.close()
		return {"R":-4}

"""
/*
 * Este subir imagen recibe un JSON con el siguiente formato
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
	#Directorio
	tmp = Path('tmp')
	if not tmp.exists():
		tmp.mkdir()
	img = Path('img')
	if not img.exists():
		img.mkdir()

	if not request.json:
		return {"R":-1}
	R = 'name' in request.json  and 'data' in request.json and 'ext' in request.json  and 'token' in request.json

	if not R:
		return {"R":-1}
	
	ext = str(request.json['ext'])
	db = getDatabase()

	TKN = request.json['token'];
	
	R = False
	try:
		with db.cursor() as cursor:
			cursor.execute('select id_Usuario from AccesoToken where token = %s', (str(TKN),))
			R = cursor.fetchall()
	except Exception:
		log.exception("Error validando token en Imagen")
		db.close()
		return {"R":-2}
	
	
	id_Usuario = R[0][0];
	with open(f'tmp/{id_Usuario}',"wb") as imagen:
		imagen.write(base64.b64decode(request.json['data'].encode()))
	
	# Guardar info del archivo en la base de datos
	try:
		with db.cursor() as cursor:
			cursor.execute('insert into Imagen values(null, %s, %s, %s)', (str(request.json["name"]), "img/", id_Usuario))
			cursor.execute('select max(id) as idImagen from Imagen where id_Usuario = %s', (id_Usuario,))
			R = cursor.fetchall()
			idImagen = R[0][0];
			cursor.execute('update Imagen set ruta = %s where id = %s', (f'img/{idImagen}.{ext}', idImagen))
			db.commit()
			# Mover archivo a su nueva locacion
			shutil.move('tmp/'+str(id_Usuario),f'img/{idImagen}.{ext}')
			return {"R":0,"D":idImagen}
	except Exception:
		log.exception("Error guardando imagen")
		db.close()
		return {"R":-3}
	
"""
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 * 		"token: "XXX",
 * 		"id": "XXX"
 * 
 * 
 * Debe retornar un Token 
 * */
"""

@post('/Descargar')
def Descargar():

	db = getDatabase()
	
	if not request.json:
		return {"R":-1}
	R = 'token' in request.json and 'id' in request.json  

	if not R:
		return {"R":-1}
	
	TKN = request.json['token'];
	idImagen = request.json['id'];
	
	R = False
	try:
		with db.cursor() as cursor:
			cursor.execute('select id_Usuario from AccesoToken where token = %s', (str(TKN),))
			R = cursor.fetchall()
	except Exception:
		log.exception("Error validando token en Descargar")
		db.close()
		return {"R":-2}
		
	# Buscar imagen y enviarla
	try:
		with db.cursor() as cursor:
			cursor.execute('Select name,ruta from  Imagen where id = %s', (idImagen,))
			R = cursor.fetchall()
	except Exception:
		log.exception("Error buscando imagen en Descargar")
		db.close()
		return {"R":-3}
	return static_file(R[0][1],Path(".").resolve())

dbg_mode = os.environ.get("APP_DBG", "false").lower() == "true"

if __name__ == '__main__':
    run(host=os.environ.get("APP_HOST", "127.0.0.1"), port=8080, debug=dbg_mode)