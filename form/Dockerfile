FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir .

RUN useradd --create-home form
USER form

ENV FORM_DATA_DIR=/data
ENV FORM_STORAGE=sqlite
VOLUME /data

EXPOSE 8000

CMD ["form-api", "--host", "0.0.0.0", "--port", "8000"]
