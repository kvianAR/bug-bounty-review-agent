FROM python:3.12-slim
RUN pip install --no-cache-dir fastapi==0.115.12 httpx==0.28.1 pytest==8.3.5 sqlalchemy==2.0.40 redis==5.2.1
