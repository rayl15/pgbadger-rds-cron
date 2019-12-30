FROM sourcefuse/pgview2:2018

#Copying files.
COPY . .

CMD ["./run.py"]