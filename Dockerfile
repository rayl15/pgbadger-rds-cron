FROM sourcefuse/pgview2:2018

RUN pip install --upgrade pip

RUN pip install --upgrade python

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

#Copying files.
COPY . .

CMD ["./run.py"]