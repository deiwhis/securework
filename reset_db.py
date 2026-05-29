import mysql.connector
import re

db = mysql.connector.connect(
    host     = "zephyr.proxy.rlwy.net",
    port     = 31734,
    user     = "root",
    password = "ZEVOmVuZFbdrEapAXoTCdypBfAjeMRtT",
    database = "railway"
)
cur = db.cursor()

print("Limpiando base de datos...")
cur.execute("SET FOREIGN_KEY_CHECKS = 0")

# Borrar triggers
for trg in ["trg_bloqueo_login", "trg_auditoria_incidente"]:
    cur.execute(f"DROP TRIGGER IF EXISTS `{trg}`")
    print(f"  Trigger eliminado: {trg}")

# Borrar procedures
for proc in ["sp_cambiar_estado_incidente", "sp_asignar_dispositivo"]:
    cur.execute(f"DROP PROCEDURE IF EXISTS `{proc}`")
    print(f"  Procedure eliminado: {proc}")

# Borrar funciones
for fn in ["fn_total_incidentes_empleado", "fn_esta_bloqueado"]:
    cur.execute(f"DROP FUNCTION IF EXISTS `{fn}`")
    print(f"  Función eliminada: {fn}")

# Borrar todas las tablas
cur.execute("SHOW TABLES")
tablas = [row[0] for row in cur.fetchall()]
for tabla in tablas:
    cur.execute(f"DROP TABLE IF EXISTS `{tabla}`")
    print(f"  Tabla eliminada: {tabla}")

cur.execute("SET FOREIGN_KEY_CHECKS = 1")
db.commit()
print("\nBase de datos limpia!\n")
cur.close()
db.close()