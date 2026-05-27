-- =========================================================
-- SecureWork — Schema completo
-- Ejecutar en MySQL Workbench como usuario root
-- =========================================================

CREATE DATABASE IF NOT EXISTS securework
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE securework;

-- ─────────────────────────────────────────
--  TABLAS BASE
-- ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS area (
  id_area     INT AUTO_INCREMENT PRIMARY KEY,
  nombre_area VARCHAR(100) NOT NULL,
  descripcion TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS empleado (
  id_empleado       INT AUTO_INCREMENT PRIMARY KEY,
  nombre            VARCHAR(80)  NOT NULL,
  apellido          VARCHAR(80)  NOT NULL,
  correo            VARCHAR(150) NOT NULL UNIQUE,
  cargo             VARCHAR(100) NOT NULL,
  estado            ENUM('activo','inactivo') DEFAULT 'activo',
  fecha_ingreso     DATE         NOT NULL,
  id_area           INT          NOT NULL,
  password_hash     VARCHAR(255) NOT NULL,
  rol               ENUM('admin','ti','seguridad','rrhh') NOT NULL,
  intentos_fallidos TINYINT UNSIGNED DEFAULT 0,
  bloqueado         TINYINT(1)   DEFAULT 0,
  created_at        DATETIME     DEFAULT CURRENT_TIMESTAMP,
  updated_at        DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_emp_area FOREIGN KEY (id_area)
    REFERENCES area(id_area) ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dispositivo (
  id_dispositivo  INT AUTO_INCREMENT PRIMARY KEY,
  tipo_dispositivo VARCHAR(80)  NOT NULL,
  marca           VARCHAR(80)  NOT NULL,
  modelo          VARCHAR(100) NOT NULL,
  serial          VARCHAR(100) NOT NULL UNIQUE,
  estado          ENUM('activo','inactivo','mantenimiento') DEFAULT 'activo',
  id_empleado     INT,
  CONSTRAINT fk_disp_emp FOREIGN KEY (id_empleado)
    REFERENCES empleado(id_empleado) ON UPDATE CASCADE ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sistema (
  id_sistema    INT AUTO_INCREMENT PRIMARY KEY,
  nombre_sistema VARCHAR(100) NOT NULL,
  descripcion   TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS acceso (
  id_acceso        INT AUTO_INCREMENT PRIMARY KEY,
  fecha_asignacion DATE         NOT NULL,
  nivel_acceso     VARCHAR(50)  NOT NULL,
  estado           ENUM('activo','inactivo') DEFAULT 'activo',
  id_empleado      INT          NOT NULL,
  id_sistema       INT          NOT NULL,
  CONSTRAINT fk_acc_emp FOREIGN KEY (id_empleado)
    REFERENCES empleado(id_empleado) ON DELETE CASCADE,
  CONSTRAINT fk_acc_sis FOREIGN KEY (id_sistema)
    REFERENCES sistema(id_sistema) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS incidente (
  id_incidente   INT AUTO_INCREMENT PRIMARY KEY,
  tipo_incidente VARCHAR(100) NOT NULL,
  descripcion    TEXT         NOT NULL,
  fecha_reporte  DATETIME     DEFAULT CURRENT_TIMESTAMP,
  estado         ENUM('abierto','en_proceso','cerrado') DEFAULT 'abierto',
  id_empleado    INT          NOT NULL,
  id_dispositivo INT,
  CONSTRAINT fk_inc_emp  FOREIGN KEY (id_empleado)
    REFERENCES empleado(id_empleado) ON DELETE RESTRICT,
  CONSTRAINT fk_inc_disp FOREIGN KEY (id_dispositivo)
    REFERENCES dispositivo(id_dispositivo) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS capacitacion (
  id_capacitacion INT AUTO_INCREMENT PRIMARY KEY,
  nombre          VARCHAR(150) NOT NULL,
  descripcion     TEXT,
  obligatoria     TINYINT(1)   DEFAULT 0,
  fecha_inicio    DATE         NOT NULL,
  fecha_fin       DATE         NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS empleado_capacitacion (
  id_empleado     INT  NOT NULL,
  id_capacitacion INT  NOT NULL,
  fecha_completado DATE,
  estado          ENUM('pendiente','en_proceso','completado') DEFAULT 'pendiente',
  PRIMARY KEY (id_empleado, id_capacitacion),
  CONSTRAINT fk_ec_emp FOREIGN KEY (id_empleado)
    REFERENCES empleado(id_empleado) ON DELETE CASCADE,
  CONSTRAINT fk_ec_cap FOREIGN KEY (id_capacitacion)
    REFERENCES capacitacion(id_capacitacion) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ─────────────────────────────────────────
--  TABLAS DE SEGURIDAD / MFA
-- ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS mfa_token (
  id_token    INT AUTO_INCREMENT PRIMARY KEY,
  id_empleado INT          NOT NULL,
  token_code  CHAR(6)      NOT NULL,
  tipo        ENUM('registro','login') NOT NULL,
  usado       TINYINT(1)   DEFAULT 0,
  expires_at  DATETIME     NOT NULL,
  created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_mfa_emp FOREIGN KEY (id_empleado)
    REFERENCES empleado(id_empleado) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sesion (
  id_sesion    INT AUTO_INCREMENT PRIMARY KEY,
  id_empleado  INT          NOT NULL,
  token_sesion VARCHAR(255) NOT NULL,
  ip_origen    VARCHAR(45),
  activa       TINYINT(1)   DEFAULT 1,
  created_at   DATETIME     DEFAULT CURRENT_TIMESTAMP,
  expires_at   DATETIME     NOT NULL,
  CONSTRAINT fk_ses_emp FOREIGN KEY (id_empleado)
    REFERENCES empleado(id_empleado) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS auditoria_acceso (
  id_auditoria INT AUTO_INCREMENT PRIMARY KEY,
  id_empleado  INT,
  correo       VARCHAR(150),
  accion       VARCHAR(100) NOT NULL,
  exitoso      TINYINT(1)   DEFAULT 0,
  ip_origen    VARCHAR(45),
  detalle      TEXT,
  fecha_hora   DATETIME     DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_audit_emp   (id_empleado),
  INDEX idx_audit_fecha (fecha_hora)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ─────────────────────────────────────────
--  PROCEDIMIENTOS ALMACENADOS
-- ─────────────────────────────────────────

DROP PROCEDURE IF EXISTS sp_cambiar_estado_incidente;
DELIMITER $$
CREATE PROCEDURE sp_cambiar_estado_incidente (
  IN  p_id_incidente INT,
  IN  p_nuevo_estado VARCHAR(20),
  IN  p_id_empleado  INT,
  OUT p_resultado    VARCHAR(100)
)
BEGIN
  DECLARE v_estado_actual VARCHAR(20);

  SELECT estado INTO v_estado_actual
  FROM incidente WHERE id_incidente = p_id_incidente;

  IF v_estado_actual IS NULL THEN
    SET p_resultado = 'ERROR: Incidente no encontrado';
  ELSEIF v_estado_actual = 'cerrado' THEN
    SET p_resultado = 'ERROR: El incidente ya está cerrado';
  ELSE
    START TRANSACTION;
      UPDATE incidente SET estado = p_nuevo_estado
      WHERE id_incidente = p_id_incidente;

      INSERT INTO auditoria_acceso (id_empleado, accion, exitoso, detalle)
      VALUES (p_id_empleado,
              CONCAT('CAMBIO_ESTADO_INCIDENTE_', p_id_incidente),
              1,
              CONCAT(v_estado_actual, ' → ', p_nuevo_estado));
    COMMIT;
    SET p_resultado = 'OK';
  END IF;
END$$
DELIMITER ;

DROP PROCEDURE IF EXISTS sp_asignar_dispositivo;
DELIMITER $$
CREATE PROCEDURE sp_asignar_dispositivo (
  IN  p_id_dispositivo INT,
  IN  p_id_empleado    INT,
  OUT p_resultado      VARCHAR(100)
)
BEGIN
  DECLARE v_actual INT;

  SELECT id_empleado INTO v_actual
  FROM dispositivo WHERE id_dispositivo = p_id_dispositivo;

  IF v_actual IS NOT NULL AND v_actual != p_id_empleado THEN
    SET p_resultado = 'ERROR: Dispositivo ya asignado a otro empleado activo';
  ELSE
    START TRANSACTION;
      UPDATE dispositivo SET id_empleado = p_id_empleado
      WHERE id_dispositivo = p_id_dispositivo;
    COMMIT;
    SET p_resultado = 'OK';
  END IF;
END$$
DELIMITER ;

-- ─────────────────────────────────────────
--  FUNCIONES
-- ─────────────────────────────────────────

DROP FUNCTION IF EXISTS fn_total_incidentes_empleado;
DELIMITER $$
CREATE FUNCTION fn_total_incidentes_empleado(p_id_empleado INT)
RETURNS INT DETERMINISTIC READS SQL DATA
BEGIN
  DECLARE total INT;
  SELECT COUNT(*) INTO total
  FROM incidente WHERE id_empleado = p_id_empleado;
  RETURN total;
END$$
DELIMITER ;

DROP FUNCTION IF EXISTS fn_esta_bloqueado;
DELIMITER $$
CREATE FUNCTION fn_esta_bloqueado(p_correo VARCHAR(150))
RETURNS TINYINT DETERMINISTIC READS SQL DATA
BEGIN
  DECLARE v_bloqueado TINYINT;
  SELECT bloqueado INTO v_bloqueado
  FROM empleado WHERE correo = p_correo LIMIT 1;
  RETURN IFNULL(v_bloqueado, 0);
END$$
DELIMITER ;

-- ─────────────────────────────────────────
--  TRIGGERS
-- ─────────────────────────────────────────

DROP TRIGGER IF EXISTS trg_bloqueo_login;
DELIMITER $$
CREATE TRIGGER trg_bloqueo_login
AFTER INSERT ON auditoria_acceso
FOR EACH ROW
BEGIN
  IF NEW.accion = 'LOGIN_FALLIDO' THEN
    UPDATE empleado
    SET   intentos_fallidos = intentos_fallidos + 1,
          bloqueado = IF(intentos_fallidos + 1 >= 5, 1, 0)
    WHERE correo = NEW.correo;
  ELSEIF NEW.accion = 'LOGIN_EXITOSO' THEN
    UPDATE empleado
    SET   intentos_fallidos = 0, bloqueado = 0
    WHERE correo = NEW.correo;
  END IF;
END$$
DELIMITER ;

DROP TRIGGER IF EXISTS trg_auditoria_incidente;
DELIMITER $$
CREATE TRIGGER trg_auditoria_incidente
AFTER UPDATE ON incidente
FOR EACH ROW
BEGIN
  IF OLD.estado != NEW.estado THEN
    INSERT INTO auditoria_acceso (accion, exitoso, detalle)
    VALUES ('INCIDENTE_ESTADO_CAMBIADO', 1,
            CONCAT('ID:', NEW.id_incidente,
                   ' | ', OLD.estado, ' → ', NEW.estado));
  END IF;
END$$
DELIMITER ;

-- ─────────────────────────────────────────
--  ROLES Y PERMISOS
-- ─────────────────────────────────────────

CREATE USER IF NOT EXISTS 'sw_app'@'localhost'      IDENTIFIED BY 'App@SecureWork1!';
CREATE USER IF NOT EXISTS 'sw_readonly'@'localhost' IDENTIFIED BY 'Read@SecureWork1!';

GRANT SELECT, INSERT, UPDATE, DELETE ON securework.* TO 'sw_app'@'localhost';
GRANT SELECT                         ON securework.* TO 'sw_readonly'@'localhost';
GRANT EXECUTE ON PROCEDURE securework.sp_cambiar_estado_incidente TO 'sw_app'@'localhost';
GRANT EXECUTE ON PROCEDURE securework.sp_asignar_dispositivo      TO 'sw_app'@'localhost';

FLUSH PRIVILEGES;

-- ─────────────────────────────────────────
--  DATOS INICIALES
-- ─────────────────────────────────────────

INSERT INTO area (nombre_area, descripcion) VALUES
  ('Tecnología de la Información', 'Gestión de infraestructura TI'),
  ('Seguridad Informática',        'Control de riesgos y amenazas'),
  ('Recursos Humanos',             'Gestión del talento humano'),
  ('Dirección General',            'Alta dirección de la empresa'),
  ('Operaciones',                  'Operaciones del negocio');

INSERT INTO sistema (nombre_sistema, descripcion) VALUES
  ('VPN Corporativa',   'Red privada virtual para acceso remoto seguro'),
  ('ERP Interno',       'Sistema de planificación de recursos empresariales'),
  ('Correo Corporativo','Plataforma de comunicación interna'),
  ('CRM',              'Gestión de relaciones con clientes');

INSERT INTO capacitacion (nombre, descripcion, obligatoria, fecha_inicio, fecha_fin) VALUES
  ('Seguridad en Trabajo Remoto',  'Buenas prácticas para empleados remotos', 1, '2026-01-15', '2026-02-15'),
  ('Phishing y Malware',           'Identificación de amenazas digitales',    1, '2026-02-01', '2026-03-01'),
  ('Manejo Seguro de Contraseñas', 'Gestión de credenciales y MFA',          0, '2026-03-01', '2026-04-01');
