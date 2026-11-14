# Book Shelf: one small Python server that serves the app and stores accounts in SQLite.
FROM python:3.12-slim
WORKDIR /app
COPY . .
ENV DATA_DIR=/data PORT=8765
RUN mkdir -p /data
EXPOSE 8765
CMD ["python3", "server.py"]
