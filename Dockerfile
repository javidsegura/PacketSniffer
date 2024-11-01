FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN pip3 install streamlit

EXPOSE 8501

CMD ["streamlit", "run", "app/utils/ddos/demoapp.py"]