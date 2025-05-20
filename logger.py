import logging
import configparser
import os


# Cargar configuración desde config.ini
config = configparser.ConfigParser()
config.read("config.ini")

# Leer ruta del archivo de log desde [logging]
log_file = config["logging"].get("log_file", "app.log")
log_level = config["logging"].get("log_level", "INFO").upper()

# Asegurarse de que el directorio del log exista
log_dir = os.path.dirname(log_file)
if log_dir and not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Configurar logging global
logging.basicConfig(
    filename=log_file,
    level=getattr(logging, log_level, logging.INFO),
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Exportar logger para uso en otros módulos
logger = logging.getLogger("virustotal_app")
