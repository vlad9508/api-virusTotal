import requests
import configparser
from logger import logger

class VirusTotalService:
    """
    Servicio para interactuar con la API pública de VirusTotal.
    Permite enviar archivos para análisis y obtener reportes usando su hash.
    """

    def __init__(self, config_file="config.ini"):
        """
        Inicializa el servicio cargando la configuración desde un archivo INI.

        Args:
            config_file (str): Ruta al archivo de configuración .ini que contiene la sección [virus_total].
        """

        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        self.config_vt = self.config["virus_total"]

    def send_file(self, file_name: str, file_data: bytes, apikey) -> dict:
        """
        Envía un archivo a VirusTotal para análisis.

        Args:
            file_name (str): Nombre del archivo original.
            file_data (bytes): Contenido del archivo en bytes.
            apikey (str): API Key de VirusTotal.

        Returns:
            dict: Respuesta en formato JSON de la API de VirusTotal.
        """

        try:
            # Construir la URL del endpoint para escanear archivos
            url = self.config_vt['URL_api'] + "file/scan"

            # Preparar archivos y parámetros
            files = {'file': (file_name, file_data)}
            params = {'apikey': apikey}

            # Enviar la solicitud
            response = requests.post(url, files=files, params=params)

            # Registrar la operación en el log
            logger.info(f"Archivo enviado a VirusTotal: {file_name}")

            return response.json()

        except Exception as e:
            # Registrar el error y relanzarlo
            logger.error(f"Error al enviar archivo a VirusTotal: {e}")
            raise

    def get_report(self, file_hash: str, apikey) -> dict:
        """
        Consulta el reporte de VirusTotal para un archivo ya escaneado.

        Args:
            file_hash (str): Hash del archivo (SHA-256, MD5 o SHA-1).
            apikey (str): API Key de VirusTotal.

        Returns:
            dict: Respuesta JSON con el reporte del análisis.
        """

        try:
            # Construir la URL del endpoint de consulta
            url = self.config_vt['URL_api'] + "file/report"

            # Preparar parámetros
            params = {'apikey': apikey, 'resource': file_hash}

            # Realizar la consulta
            response = requests.get(url, params=params)

            # Registrar la operación en el log
            logger.info(f"Consulta de reporte para hash: {file_hash}")

            return response.json()

        except Exception as e:
            # Registrar y relanzar el error
            logger.error(f"Error al consultar reporte en VirusTotal: {e}")
            raise
