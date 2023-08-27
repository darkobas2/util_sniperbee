FROM python:3.11

ARG PORT=80
ENV PORT=$PORT

RUN mkdir /app
WORKDIR /app
RUN chown nobody /app
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY sniperbee.py .
USER nobody
CMD waitress-serve --port=${PORT} sniperbee:app
EXPOSE ${PORT}
