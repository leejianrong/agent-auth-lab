FROM python:3.12-slim
WORKDIR /app
COPY --from=harness . /harness
COPY requirements.txt .
RUN grep -v '^-e' requirements.txt > requirements.docker.txt \
    && pip install --no-cache-dir -r requirements.docker.txt /harness
COPY . .
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
