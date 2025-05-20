# api-virusTotal

# VirusTotal FastAPI API

API REST desarrollada con **FastAPI** para analizar archivos usando la API pública de **VirusTotal**.  
Permite subir archivos, calcular su hash SHA-256 y consultar si han sido analizados previamente.  
Si no lo han sido, se envían automáticamente para escaneo.

---

## Instrucciones de compilación y ejecución (Docker)

### Estructura esperada

```
project-root/
├── main.py
├── config.ini
├── logger.py
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── routes/
│   └── routes.py
├── services/
│   ├── hash_service.py
│   └── virus_total_service.py
```

### 1. Construir imagen Docker

```bash
docker-compose build
```

### 2. Ejecutar contenedor

```bash
docker-compose up
```

### 3. Detener contenedor

```bash
docker-compose down
```

---

## Documentación de la API

### `POST /api/analyze`

Analiza un archivo con VirusTotal.

#### Parámetros (form-data)

| Nombre   | Tipo    | Descripción                        |
|----------|---------|------------------------------------|
| `file`   | `File`  | Archivo a analizar                 |
| `apikey` | `Text`  | Tu API key de VirusTotal           |

#### Ejemplo de uso con `curl`:

```bash
curl -X POST http://localhost:8000/api/analyze \
  -F "file=@ejemplo.pdf" \
  -F "apikey=TU_API_KEY"
```

#### Posibles respuestas

| Código | Significado                                             |
|--------|---------------------------------------------------------|
| 200    | Archivo ya había sido analizado (devuelve el reporte)  |
| 202    | Archivo enviado a VirusTotal (esperar 1 min)           |
| 500    | Error inesperado (problemas de conexión o API Key)     |

## Ejemplo de `config.ini`

```ini
[virus_total]
URL_api = https://www.virustotal.com/vtapi/v2/

[logging]
log_file = logs/app.log
log_level = INFO
```

---

## Suposiciones realizadas

- La API key se proporciona **en cada solicitud** como un campo `form-data` llamado `apikey`.
- Se utiliza la **API pública de VirusTotal v2** (limitada a 4 requests/min).
- El archivo se considera único por su **hash SHA-256**.
- Si el hash ya existe en VirusTotal, se devuelve el reporte inmediatamente.
- Si no existe, se envía el archivo y se solicita reintentar más tarde.

