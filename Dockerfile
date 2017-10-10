FROM python:2

ADD * ./

RUN pip install -r requirements.txt

ENTRYPOINT ["python","a2sv.py"]
