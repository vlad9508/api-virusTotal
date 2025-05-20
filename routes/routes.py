from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from services.hash_services import HashService
from services.virus_total_service import VirusTotalService
from logger import logger

# Instancia del router y servicios auxiliares
router = APIRouter()
hash_service = HashService()
vt_service = VirusTotalService()

@router.post("/analyze")
async def analyze_file(file: UploadFile = File(...), apikey: str = Form(...)):
    """
    Recibe un archivo, calcula su hash y consulta VirusTotal.
    Si el archivo no ha sido analizado antes, lo envía a VirusTotal para análisis.

    Args:
        file (UploadFile): Archivo cargado por el usuario (form-data).
        apikey (str): API key de VirusTotal proporcionada por el usuario (form-data).

    Returns:
        JSON: Respuesta con el reporte de análisis o estado de envío.
    """
    try:
        # Leer bytes del archivo
        file_bytes = await file.read()

        # Obtener hash SHA-256
        sha256 = hash_service.get_sha256(file_bytes)

        # Consultar reporte en VirusTotal
        report = vt_service.get_report(sha256, apikey)

        if report.get('response_code') == 0:
            # Si no hay resultado previo, enviarlo
            vt_service.send_file(file.filename, file_bytes, apikey)
            logger.info(f"Archivo {file.filename} enviado a VirusTotal.")
            return {"message": "Archivo enviado a VirusTotal. Intenta nuevamente en 1 minuto."}
        
        # Si ya fue analizado, devolver el informe
        logger.info(f"Archivo {file.filename} ya fue analizado.")
        return {"message": "Archivo ya analizado", "report": report}
    except Exception as e:
        logger.error(f"Error en análisis de archivo: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
