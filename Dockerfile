FROM python:latest

WORKDIR /Password-Manager/

COPY requirements.txt .

RUN pip install -r requirements.txt

COPY password_manager .  

CMD [ "python", "password_manager" ]