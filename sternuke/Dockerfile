# sternuke — headless CLI + web dashboard image (native Tk GUI intentionally excluded).
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY . /app
# Core deps (incl. aiohttp for the dashboard) + CLI + numpy. Create a non-root user
# and a writable output directory it owns (the app writes findings/advisories there).
RUN pip install --no-cache-dir . click numpy \
    && useradd --create-home --uid 10001 sternuke \
    && mkdir -p /app/sternuke-out \
    && chown -R sternuke:sternuke /app/sternuke-out
USER sternuke
EXPOSE 8787
ENTRYPOINT ["sternuke"]
# Bind 0.0.0.0 INSIDE the container only; publish to the host with -p.
CMD ["serve", "--host", "0.0.0.0", "--port", "8787"]
