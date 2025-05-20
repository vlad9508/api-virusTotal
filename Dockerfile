# Usar una imagen base de Python 3.9.13
FROM python:3.9.13

# Establecer el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copiar los archivos de la aplicación
COPY . .

# Instalar dependencias
RUN pip install --no-cache-dir --upgrade pip \
    && pip install -r requirements.txt

# Exponer el puerto en el que correrá FastAPI
EXPOSE 8000

# Comando para ejecutar la aplicación
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
