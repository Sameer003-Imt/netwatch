FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python scripts/make_sample_pcap.py
ENTRYPOINT ["python", "-m","netwatch"]
CMD ["--pcap","samples/demo.pcap","--quiet"]

