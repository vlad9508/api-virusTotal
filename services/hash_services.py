import hashlib
from logger import logger

class HashService:
    """
    Servicio para calcular hashes criptográficos de archivos.
    Actualmente implementa hash SHA-256.
    """
    def get_sha256(self, file_data: bytes) -> str:
        """
        Calcula el hash SHA-256 de un archivo dado.

        Args:
            file_data (bytes): Contenido binario del archivo.

        Returns:
            str: Cadena hexadecimal del hash SHA-256.
        """
        # Calcular el hash
        sha256_hash = hashlib.sha256(file_data).hexdigest()

        # Registrar el resultado en logs
        logger.info(f"Hash SHA-256 calculado: {sha256_hash}")

        return sha256_hash
