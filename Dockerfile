FROM sourcefuse/pgview2:2018

# Copy new Pgbadger

COPY . .

CMD ["./run.py"]