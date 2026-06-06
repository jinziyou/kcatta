FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir .

RUN useradd --create-home form
# Create + own the data dir BEFORE switching user, so the non-root `form` user can
# write /data/form.db (the VOLUME mountpoint would otherwise be root-owned).
RUN mkdir -p /data && chown form:form /data
USER form

ENV FORM_DATA_DIR=/data
ENV FORM_STORAGE=sqlite
VOLUME /data

EXPOSE 8000

CMD ["form-api", "--host", "0.0.0.0", "--port", "8000"]
