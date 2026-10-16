FROM python:3.12-slim
WORKDIR /app
# The shared observability harness comes from a named build context (see docker-compose.yml).
COPY --from=harness . /harness
COPY requirements.txt .
RUN grep -v '^-e' requirements.txt > requirements.docker.txt \
    && pip install --no-cache-dir -r requirements.docker.txt /harness
COPY . .
CMD ["uvicorn", "lab_idp.main:app", "--host", "0.0.0.0", "--port", "9000"]
