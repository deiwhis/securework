from flask import Flask, request, jsonify, render_template, session
from flask_cors import CORS
from dotenv import load_dotenv
import mysql.connector
import bcrypt
import random
import string
import os
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "clave_super_secreta_2026")
CORS(app)

# ─────────────────────────────────────────
#  Conexión a MySQL
# ─────────────────────────────────────────
def get_db():
    return mysql.connector.connect(
        host     = os.getenv("MYSQL_HOST", "localhost"),
        user     = os.getenv("MYSQL_USER", "root"),
        password = os.getenv("MYSQL_PASSWORD", ""),
        database = os.getenv("MYSQL_DB", "securework"),
        charset  = "utf8mb4"
    )

# ─────────────────────────────────────────
#  Utilidades
# ─────────────────────────────────────────
def generar_otp():
    return ''.join(random.choices(string.digits, k=6))

def enviar_otp_email(destinatario, otp, tipo="registro"):
    """
    En desarrollo: imprime el OTP en consola.
    En producción: configura SMTP_USER y SMTP_PASS en .env
    """
    print(f"\n{'='*40}")
    print(f"  OTP de {tipo.upper()} para {destinatario}: {otp}")
    print(f"{'='*40}\n")

    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    if not smtp_user:
        return  # Solo consola en modo dev

    try:
        msg = MIMEText(
            f"Tu código de verificación SecureWork es: {otp}\n"
            f"Válido por 2 minutos. No lo compartas con nadie."
        )
        msg["Subject"] = f"[SecureWork] Código de {tipo}"
        msg["From"]    = smtp_user
        msg["To"]      = destinatario
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
            s.login(smtp_user, smtp_pass)
            s.sendmail(smtp_user, destinatario, msg.as_string())
    except Exception as e:
        print("Error enviando email:", e)

def registrar_auditoria(cursor, id_empleado, correo, accion, exitoso, ip=None, detalle=None):
    cursor.execute(
        """INSERT INTO auditoria_acceso
           (id_empleado, correo, accion, exitoso, ip_origen, detalle)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (id_empleado, correo, accion, exitoso, ip, detalle)
    )

# ─────────────────────────────────────────
#  Página principal
# ─────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

# ─────────────────────────────────────────
#  REGISTRO — Paso 1: guardar datos + enviar OTP
# ─────────────────────────────────────────
@app.route("/api/registro/iniciar", methods=["POST"])
def registro_iniciar():
    data = request.get_json()
    correo    = data.get("correo", "").strip().lower()
    password  = data.get("password", "")
    rol       = data.get("rol", "")
    nombre    = data.get("nombre", "").strip()
    apellido  = data.get("apellido", "").strip()
    cargo     = data.get("cargo", "").strip()
    id_area   = data.get("id_area")
    fecha_ing = data.get("fecha_ingreso")
    estado    = data.get("estado", "activo")

    # Validaciones básicas
    if not all([correo, password, rol, nombre, apellido, cargo, id_area, fecha_ing]):
        return jsonify({"ok": False, "msg": "Faltan campos obligatorios"}), 400
    if len(password) < 8:
        return jsonify({"ok": False, "msg": "La contraseña debe tener mínimo 8 caracteres"}), 400

    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        # Verificar correo único
        cur.execute("SELECT id_empleado FROM empleado WHERE correo = %s", (correo,))
        if cur.fetchone():
            return jsonify({"ok": False, "msg": "El correo ya está registrado"}), 409

        # Hash de contraseña
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        # Insertar empleado
        cur.execute(
            """INSERT INTO empleado
               (nombre, apellido, correo, cargo, estado, fecha_ingreso,
                id_area, password_hash, rol)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (nombre, apellido, correo, cargo, estado,
             fecha_ing, id_area, pw_hash, rol)
        )
        id_emp = cur.lastrowid

        # Generar y guardar OTP
        otp = generar_otp()
        cur.execute(
            """INSERT INTO mfa_token
               (id_empleado, token_code, tipo, expires_at)
               VALUES (%s, %s, 'registro',
                       DATE_ADD(NOW(), INTERVAL 2 MINUTE))""",
            (id_emp, otp)
        )

        # Auditoría
        registrar_auditoria(cur, id_emp, correo, "REGISTRO_INICIADO", 0,
                            request.remote_addr)
        db.commit()

        # Enviar OTP (consola en dev, email en prod)
        enviar_otp_email(correo, otp, "registro")

        return jsonify({"ok": True, "id_empleado": id_emp,
                        "msg": "OTP enviado al correo"})

    except Exception as e:
        db.rollback()
        return jsonify({"ok": False, "msg": str(e)}), 500
    finally:
        cur.close(); db.close()

# ─────────────────────────────────────────
#  REGISTRO — Paso 2: verificar OTP
# ─────────────────────────────────────────
@app.route("/api/registro/verificar", methods=["POST"])
def registro_verificar():
    data       = request.get_json()
    id_emp     = data.get("id_empleado")
    otp_ingres = data.get("otp", "")

    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute(
            """SELECT id_token FROM mfa_token
               WHERE id_empleado=%s AND token_code=%s
                 AND tipo='registro' AND usado=0
                 AND expires_at > NOW()""",
            (id_emp, otp_ingres)
        )
        token = cur.fetchone()

        if not token:
            return jsonify({"ok": False,
                            "msg": "Código incorrecto o expirado"}), 401

        # Marcar token usado
        cur.execute("UPDATE mfa_token SET usado=1 WHERE id_token=%s",
                    (token["id_token"],))

        # Auditoría: registro completado
        cur.execute(
            """UPDATE auditoria_acceso SET exitoso=1
               WHERE id_empleado=%s AND accion='REGISTRO_INICIADO'
               ORDER BY fecha_hora DESC LIMIT 1""",
            (id_emp,)
        )
        db.commit()
        return jsonify({"ok": True, "msg": "Cuenta verificada correctamente"})

    except Exception as e:
        db.rollback()
        return jsonify({"ok": False, "msg": str(e)}), 500
    finally:
        cur.close(); db.close()

# ─────────────────────────────────────────
#  REGISTRO — Reenviar OTP
# ─────────────────────────────────────────
@app.route("/api/registro/reenviar", methods=["POST"])
def registro_reenviar():
    data   = request.get_json()
    id_emp = data.get("id_empleado")

    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT correo FROM empleado WHERE id_empleado=%s", (id_emp,))
        emp = cur.fetchone()
        if not emp:
            return jsonify({"ok": False, "msg": "Empleado no encontrado"}), 404

        otp = generar_otp()
        cur.execute(
            """INSERT INTO mfa_token
               (id_empleado, token_code, tipo, expires_at)
               VALUES (%s, %s, 'registro',
                       DATE_ADD(NOW(), INTERVAL 2 MINUTE))""",
            (id_emp, otp)
        )
        db.commit()
        enviar_otp_email(emp["correo"], otp, "registro")
        return jsonify({"ok": True, "msg": "Nuevo OTP enviado"})

    except Exception as e:
        db.rollback()
        return jsonify({"ok": False, "msg": str(e)}), 500
    finally:
        cur.close(); db.close()

# ─────────────────────────────────────────
#  LOGIN — Paso 1: verificar credenciales
# ─────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    data     = request.get_json()
    correo   = data.get("correo", "").strip().lower()
    password = data.get("password", "")
    ip       = request.remote_addr

    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute(
            """SELECT id_empleado, nombre, apellido, rol,
                      password_hash, bloqueado, intentos_fallidos
               FROM empleado WHERE correo=%s""",
            (correo,)
        )
        emp = cur.fetchone()

        if not emp:
            return jsonify({"ok": False,
                            "msg": "Credenciales incorrectas"}), 401

        if emp["bloqueado"]:
            return jsonify({"ok": False,
                            "msg": "Cuenta bloqueada por múltiples intentos fallidos. "
                                   "Contacta al administrador."}), 403

        # Verificar contraseña
        pw_ok = bcrypt.checkpw(password.encode(),
                                emp["password_hash"].encode())

        if not pw_ok:
            registrar_auditoria(cur, emp["id_empleado"], correo,
                                "LOGIN_FALLIDO", 0, ip)
            db.commit()
            intentos = emp["intentos_fallidos"] + 1
            restantes = max(0, 5 - intentos)
            return jsonify({
                "ok": False,
                "msg": f"Contraseña incorrecta. {restantes} intentos restantes."
            }), 401

        # Generar OTP de login
        otp = generar_otp()
        cur.execute(
            """INSERT INTO mfa_token
               (id_empleado, token_code, tipo, expires_at)
               VALUES (%s, %s, 'login',
                       DATE_ADD(NOW(), INTERVAL 2 MINUTE))""",
            (emp["id_empleado"], otp)
        )
        db.commit()
        enviar_otp_email(correo, otp, "login")

        return jsonify({
            "ok":          True,
            "id_empleado": emp["id_empleado"],
            "nombre":      emp["nombre"],
            "apellido":    emp["apellido"],
            "msg":         "OTP de verificación enviado"
        })

    except Exception as e:
        db.rollback()
        return jsonify({"ok": False, "msg": str(e)}), 500
    finally:
        cur.close(); db.close()

# ─────────────────────────────────────────
#  LOGIN — Paso 2: verificar OTP
# ─────────────────────────────────────────
@app.route("/api/login/verificar", methods=["POST"])
def login_verificar():
    data       = request.get_json()
    id_emp     = data.get("id_empleado")
    otp_ingres = data.get("otp", "")
    ip         = request.remote_addr

    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute(
            """SELECT id_token FROM mfa_token
               WHERE id_empleado=%s AND token_code=%s
                 AND tipo='login' AND usado=0
                 AND expires_at > NOW()""",
            (id_emp, otp_ingres)
        )
        token = cur.fetchone()

        if not token:
            return jsonify({"ok": False,
                            "msg": "Código incorrecto o expirado"}), 401

        cur.execute("UPDATE mfa_token SET usado=1 WHERE id_token=%s",
                    (token["id_token"],))

        # Obtener datos del empleado para la sesión
        cur.execute(
            "SELECT nombre, apellido, rol, correo FROM empleado WHERE id_empleado=%s",
            (id_emp,)
        )
        emp = cur.fetchone()

        registrar_auditoria(cur, id_emp, emp["correo"],
                            "LOGIN_EXITOSO", 1, ip)
        db.commit()

        # Guardar sesión Flask
        session["id_empleado"] = id_emp
        session["rol"]         = emp["rol"]
        session["nombre"]      = emp["nombre"]

        return jsonify({
            "ok":          True,
            "id_empleado": id_emp,
            "nombre":      emp["nombre"],
            "apellido":    emp["apellido"],
            "rol":         emp["rol"],
            "redirect":    "/dashboard",
            "msg":         "Sesión iniciada correctamente"
        })

    except Exception as e:
        db.rollback()
        return jsonify({"ok": False, "msg": str(e)}), 500
    finally:
        cur.close(); db.close()

# ─────────────────────────────────────────
#  LOGOUT
# ─────────────────────────────────────────
@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True, "msg": "Sesión cerrada"})

# ─────────────────────────────────────────
#  ÁREAS (para el selector del formulario)
# ─────────────────────────────────────────
@app.route("/api/areas", methods=["GET"])
def get_areas():
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT id_area, nombre_area FROM area ORDER BY nombre_area")
        areas = cur.fetchall()
        return jsonify({"ok": True, "areas": areas})
    finally:
        cur.close(); db.close()

# ═══════════════════════════════════════════════════════════
#  DASHBOARD — página
# ═══════════════════════════════════════════════════════════
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

# ═══════════════════════════════════════════════════════════
#  DASHBOARD — resumen KPI
# ═══════════════════════════════════════════════════════════
@app.route("/api/dashboard/resumen", methods=["GET"])
def dashboard_resumen():
    db = get_db(); cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT COUNT(*) c FROM empleado WHERE estado='activo'")
        emp = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) c FROM dispositivo")
        disp = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) c FROM incidente WHERE estado='abierto'")
        inc = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) c FROM capacitacion")
        cap = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) c FROM sistema")
        sis = cur.fetchone()["c"]
        cur.execute("SELECT COUNT(*) c FROM acceso WHERE estado='activo'")
        acc = cur.fetchone()["c"]
        cur.execute("""SELECT a.accion, a.correo, a.exitoso, a.ip_origen,
                              DATE_FORMAT(a.fecha_hora,'%d/%m %H:%i') fecha_hora
                       FROM auditoria_acceso a ORDER BY a.fecha_hora DESC LIMIT 8""")
        actividad = cur.fetchall()
        cur.execute("""SELECT i.tipo_incidente, i.estado,
                              DATE_FORMAT(i.fecha_reporte,'%d/%m %H:%i') fecha_reporte,
                              CONCAT(e.nombre,' ',e.apellido) nombre
                       FROM incidente i
                       JOIN empleado e ON e.id_empleado=i.id_empleado
                       WHERE i.estado='abierto' LIMIT 5""")
        incidentes = cur.fetchall()
        return jsonify({"ok": True, "resumen": {
            "empleados_activos": emp, "dispositivos": disp,
            "incidentes_abiertos": inc, "capacitaciones": cap,
            "sistemas": sis, "accesos_activos": acc
        }, "actividad": actividad, "incidentes": incidentes})
    finally:
        cur.close(); db.close()

# ═══════════════════════════════════════════════════════════
#  EMPLEADOS
# ═══════════════════════════════════════════════════════════
@app.route("/api/empleados", methods=["GET"])
def get_empleados():
    db = get_db(); cur = db.cursor(dictionary=True)
    try:
        cur.execute("""SELECT e.*, a.nombre_area
                       FROM empleado e
                       LEFT JOIN area a ON a.id_area=e.id_area
                       ORDER BY e.nombre""")
        return jsonify({"ok": True, "empleados": cur.fetchall()})
    finally:
        cur.close(); db.close()

# ═══════════════════════════════════════════════════════════
#  DISPOSITIVOS
# ═══════════════════════════════════════════════════════════
@app.route("/api/dispositivos", methods=["GET"])
def get_dispositivos():
    db = get_db(); cur = db.cursor(dictionary=True)
    try:
        cur.execute("""SELECT d.*,
                              CONCAT(e.nombre,' ',e.apellido) nombre_empleado
                       FROM dispositivo d
                       LEFT JOIN empleado e ON e.id_empleado=d.id_empleado
                       ORDER BY d.id_dispositivo DESC""")
        return jsonify({"ok": True, "dispositivos": cur.fetchall()})
    finally:
        cur.close(); db.close()

@app.route("/api/dispositivos", methods=["POST"])
def crear_dispositivo():
    data = request.get_json()
    db = get_db(); cur = db.cursor()
    try:
        cur.execute("SELECT 1 FROM dispositivo WHERE serial=%s", (data["serial"],))
        if cur.fetchone():
            return jsonify({"ok": False, "msg": "El serial ya existe"}), 409
        cur.execute("""INSERT INTO dispositivo
                       (tipo_dispositivo,marca,modelo,serial,estado,id_empleado)
                       VALUES(%s,%s,%s,%s,%s,%s)""",
                    (data["tipo_dispositivo"], data["marca"], data["modelo"],
                     data["serial"], data.get("estado","activo"),
                     data.get("id_empleado") or None))
        db.commit()
        registrar_auditoria(cur, None, None, "DISPOSITIVO_CREADO", 1,
                            request.remote_addr, data["serial"])
        db.commit()
        return jsonify({"ok": True, "id": cur.lastrowid})
    except Exception as e:
        db.rollback(); return jsonify({"ok": False, "msg": str(e)}), 500
    finally:
        cur.close(); db.close()

@app.route("/api/dispositivos/<int:id>", methods=["PUT"])
def actualizar_dispositivo(id):
    data = request.get_json()
    db = get_db(); cur = db.cursor()
    try:
        cur.execute("""UPDATE dispositivo SET tipo_dispositivo=%s, marca=%s,
                       modelo=%s, serial=%s, estado=%s, id_empleado=%s
                       WHERE id_dispositivo=%s""",
                    (data["tipo_dispositivo"], data["marca"], data["modelo"],
                     data["serial"], data["estado"],
                     data.get("id_empleado") or None, id))
        db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        db.rollback(); return jsonify({"ok": False, "msg": str(e)}), 500
    finally:
        cur.close(); db.close()

@app.route("/api/dispositivos/<int:id>", methods=["DELETE"])
def eliminar_dispositivo(id):
    db = get_db(); cur = db.cursor()
    try:
        cur.execute("DELETE FROM dispositivo WHERE id_dispositivo=%s", (id,))
        db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        db.rollback(); return jsonify({"ok": False, "msg": str(e)}), 500
    finally:
        cur.close(); db.close()

# ═══════════════════════════════════════════════════════════
#  SISTEMAS
# ═══════════════════════════════════════════════════════════
@app.route("/api/sistemas", methods=["GET"])
def get_sistemas():
    db = get_db(); cur = db.cursor(dictionary=True)
    try:
        cur.execute("""SELECT s.*, COUNT(a.id_acceso) total_accesos
                       FROM sistema s
                       LEFT JOIN acceso a ON a.id_sistema=s.id_sistema AND a.estado='activo'
                       GROUP BY s.id_sistema ORDER BY s.nombre_sistema""")
        return jsonify({"ok": True, "sistemas": cur.fetchall()})
    finally:
        cur.close(); db.close()

@app.route("/api/sistemas", methods=["POST"])
def crear_sistema():
    data = request.get_json()
    db = get_db(); cur = db.cursor()
    try:
        cur.execute("INSERT INTO sistema (nombre_sistema, descripcion) VALUES(%s,%s)",
                    (data["nombre_sistema"], data.get("descripcion","")))
        db.commit()
        return jsonify({"ok": True, "id": cur.lastrowid})
    except Exception as e:
        db.rollback(); return jsonify({"ok": False, "msg": str(e)}), 500
    finally:
        cur.close(); db.close()

# ═══════════════════════════════════════════════════════════
#  ACCESOS
# ═══════════════════════════════════════════════════════════
@app.route("/api/accesos", methods=["GET"])
def get_accesos():
    db = get_db(); cur = db.cursor(dictionary=True)
    try:
        cur.execute("""SELECT ac.*,
                              CONCAT(e.nombre,' ',e.apellido) nombre_empleado,
                              s.nombre_sistema
                       FROM acceso ac
                       JOIN empleado e ON e.id_empleado=ac.id_empleado
                       JOIN sistema  s ON s.id_sistema=ac.id_sistema
                       ORDER BY ac.id_acceso DESC""")
        return jsonify({"ok": True, "accesos": cur.fetchall()})
    finally:
        cur.close(); db.close()

@app.route("/api/accesos", methods=["POST"])
def crear_acceso():
    data = request.get_json()
    db = get_db(); cur = db.cursor()
    try:
        cur.execute("""INSERT INTO acceso
                       (id_empleado, id_sistema, nivel_acceso, fecha_asignacion, estado)
                       VALUES(%s,%s,%s,%s,'activo')""",
                    (data["id_empleado"], data["id_sistema"],
                     data["nivel_acceso"], data["fecha_asignacion"]))
        db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        db.rollback(); return jsonify({"ok": False, "msg": str(e)}), 500
    finally:
        cur.close(); db.close()

@app.route("/api/accesos/<int:id>", methods=["PUT"])
def actualizar_acceso(id):
    data = request.get_json()
    db = get_db(); cur = db.cursor()
    try:
        cur.execute("UPDATE acceso SET estado=%s WHERE id_acceso=%s",
                    (data["estado"], id))
        db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        db.rollback(); return jsonify({"ok": False, "msg": str(e)}), 500
    finally:
        cur.close(); db.close()

# ═══════════════════════════════════════════════════════════
#  INCIDENTES
# ═══════════════════════════════════════════════════════════
@app.route("/api/incidentes", methods=["GET"])
def get_incidentes():
    db = get_db(); cur = db.cursor(dictionary=True)
    try:
        cur.execute("""SELECT i.*,
                              CONCAT(e.nombre,' ',e.apellido) nombre_empleado,
                              CONCAT(d.marca,' ',d.modelo)    nombre_dispositivo,
                              DATE_FORMAT(i.fecha_reporte,'%Y-%m-%d %H:%i') fecha_reporte
                       FROM incidente i
                       JOIN empleado e  ON e.id_empleado=i.id_empleado
                       LEFT JOIN dispositivo d ON d.id_dispositivo=i.id_dispositivo
                       ORDER BY i.fecha_reporte DESC""")
        return jsonify({"ok": True, "incidentes": cur.fetchall()})
    finally:
        cur.close(); db.close()

@app.route("/api/incidentes", methods=["POST"])
def crear_incidente():
    data = request.get_json()
    db = get_db(); cur = db.cursor()
    try:
        cur.execute("""INSERT INTO incidente
                       (tipo_incidente, descripcion, id_empleado, id_dispositivo)
                       VALUES(%s,%s,%s,%s)""",
                    (data["tipo_incidente"], data["descripcion"],
                     data["id_empleado"], data.get("id_dispositivo") or None))
        db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        db.rollback(); return jsonify({"ok": False, "msg": str(e)}), 500
    finally:
        cur.close(); db.close()

@app.route("/api/incidentes/<int:id>", methods=["PUT"])
def actualizar_incidente(id):
    data = request.get_json()
    db = get_db(); cur = db.cursor()
    try:
        # Usa el procedimiento almacenado sp_cambiar_estado_incidente
        cur.callproc("sp_cambiar_estado_incidente",
                     [id, data["estado"],
                      data.get("id_empleado", 1), ""])
        db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        db.rollback(); return jsonify({"ok": False, "msg": str(e)}), 500
    finally:
        cur.close(); db.close()

# ═══════════════════════════════════════════════════════════
#  AUDITORÍA
# ═══════════════════════════════════════════════════════════
@app.route("/api/auditoria", methods=["GET"])
def get_auditoria():
    db = get_db(); cur = db.cursor(dictionary=True)
    try:
        cur.execute("""SELECT a.*,
                              DATE_FORMAT(a.fecha_hora,'%Y-%m-%d %H:%i:%s') fecha_hora
                       FROM auditoria_acceso a
                       ORDER BY a.fecha_hora DESC LIMIT 100""")
        return jsonify({"ok": True, "registros": cur.fetchall()})
    finally:
        cur.close(); db.close()

# ═══════════════════════════════════════════════════════════
#  CAPACITACIONES
# ═══════════════════════════════════════════════════════════
@app.route("/api/capacitaciones", methods=["GET"])
def get_capacitaciones():
    db = get_db(); cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT * FROM capacitacion ORDER BY fecha_inicio DESC")
        return jsonify({"ok": True, "capacitaciones": cur.fetchall()})
    finally:
        cur.close(); db.close()

@app.route("/api/capacitaciones", methods=["POST"])
def crear_capacitacion():
    data = request.get_json()
    db = get_db(); cur = db.cursor()
    try:
        cur.execute("""INSERT INTO capacitacion
                       (nombre, descripcion, obligatoria, fecha_inicio, fecha_fin)
                       VALUES(%s,%s,%s,%s,%s)""",
                    (data["nombre"], data.get("descripcion",""),
                     data.get("obligatoria", 0),
                     data["fecha_inicio"], data["fecha_fin"]))
        db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        db.rollback(); return jsonify({"ok": False, "msg": str(e)}), 500
    finally:
        cur.close(); db.close()

@app.route("/api/capacitaciones/<int:id>", methods=["DELETE"])
def eliminar_capacitacion(id):
    db = get_db(); cur = db.cursor()
    try:
        cur.execute("DELETE FROM capacitacion WHERE id_capacitacion=%s", (id,))
        db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        db.rollback(); return jsonify({"ok": False, "msg": str(e)}), 500
    finally:
        cur.close(); db.close()

# ═══════════════════════════════════════════════════════════
#  EMPLEADO - CAPACITACIÓN
# ═══════════════════════════════════════════════════════════
@app.route("/api/empleado-capacitacion", methods=["GET"])
def get_emp_cap():
    db = get_db(); cur = db.cursor(dictionary=True)
    try:
        cur.execute("""SELECT ec.*,
                              CONCAT(e.nombre,' ',e.apellido) nombre_empleado,
                              c.nombre nombre_capacitacion
                       FROM empleado_capacitacion ec
                       JOIN empleado     e ON e.id_empleado=ec.id_empleado
                       JOIN capacitacion c ON c.id_capacitacion=ec.id_capacitacion
                       ORDER BY ec.id_empleado""")
        return jsonify({"ok": True, "progresos": cur.fetchall()})
    finally:
        cur.close(); db.close()

@app.route("/api/empleado-capacitacion", methods=["POST"])
def crear_emp_cap():
    data = request.get_json()
    db = get_db(); cur = db.cursor()
    try:
        cur.execute("""INSERT INTO empleado_capacitacion
                       (id_empleado, id_capacitacion, estado, fecha_completado)
                       VALUES(%s,%s,%s,%s)
                       ON DUPLICATE KEY UPDATE estado=%s, fecha_completado=%s""",
                    (data["id_empleado"], data["id_capacitacion"],
                     data.get("estado","pendiente"), data.get("fecha_completado"),
                     data.get("estado","pendiente"), data.get("fecha_completado")))
        db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        db.rollback(); return jsonify({"ok": False, "msg": str(e)}), 500
    finally:
        cur.close(); db.close()

@app.route("/api/empleado-capacitacion/<int:id_emp>/<int:id_cap>", methods=["PUT"])
def actualizar_emp_cap(id_emp, id_cap):
    data = request.get_json()
    db = get_db(); cur = db.cursor()
    try:
        cur.execute("""UPDATE empleado_capacitacion
                       SET estado=%s, fecha_completado=%s
                       WHERE id_empleado=%s AND id_capacitacion=%s""",
                    (data["estado"], data.get("fecha_completado"), id_emp, id_cap))
        db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        db.rollback(); return jsonify({"ok": False, "msg": str(e)}), 500
    finally:
        cur.close(); db.close()

# ═══════════════════════════════════════════════════════════
#  ÁREAS — detalle con conteo de empleados
# ═══════════════════════════════════════════════════════════
@app.route("/api/areas-detalle", methods=["GET"])
def get_areas_detalle():
    db = get_db(); cur = db.cursor(dictionary=True)
    try:
        cur.execute("""SELECT a.*, COUNT(e.id_empleado) total_empleados
                       FROM area a
                       LEFT JOIN empleado e ON e.id_area=a.id_area
                       GROUP BY a.id_area ORDER BY a.nombre_area""")
        return jsonify({"ok": True, "areas": cur.fetchall()})
    finally:
        cur.close(); db.close()

@app.route("/api/areas", methods=["POST"])
def crear_area():
    data = request.get_json()
    db = get_db(); cur = db.cursor()
    try:
        cur.execute("INSERT INTO area (nombre_area, descripcion) VALUES(%s,%s)",
                    (data["nombre_area"], data.get("descripcion","")))
        db.commit()
        return jsonify({"ok": True})
    except Exception as e:
        db.rollback(); return jsonify({"ok": False, "msg": str(e)}), 500
    finally:
        cur.close(); db.close()


# ─────────────────────────────────────────
#  RUN
# ─────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)