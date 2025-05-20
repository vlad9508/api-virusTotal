from fastapi import FastAPI
from routes import routes
from logger import logger

# Crear instancia principal de FastAPI
app = FastAPI(
    title="API de Análisis con VirusTotal",
    description="Permite subir archivos para escanearlos con VirusTotal.",
    version="1.0.0"
)

# Incluir las rutas desde el módulo file_routes
app.include_router(routes.router, prefix="/api")

# Registrar mensaje de inicio en el log
logger.info("Aplicación FastAPI de VirusTotal iniciada.")
