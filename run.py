#!/usr/local/bin/python
import traceback

import schedule
import time
import os
import subprocess
import psutil
import boto3
import pickle
import sys, base64, datetime, hashlib, hmac, urllib
import requests # pip install requests

#from datetime import datetime
from operator import itemgetter


rds = boto3.client('rds', region_name=os.getenv('REGION', 'us-west-2'))

log_state = dict()


def raiser(e):
    raise e

def download_log_files(db_name):
    #+++++++++++++++++++++++++++++++++++++++++
    os.system('aws configure set aws_access_key_id "'+ os.getenv('AWS_ACCESS_KEY_ID') +'"')
    os.system('aws configure set aws_secret_access_key "'+ os.getenv('AWS_SECRET_ACCESS_KEY') +'"')
    os.system('aws configure set default.region "'+ os.getenv('REGION') +'"')
    # ************* REQUEST VALUES *************
    # method = 'GET'
    # service = 'rds'
    # host = 'rds.us-west-2.amazonaws.com'
    # region = os.getenv('REGION')
    # endpoint = 'https://' + host
    # db_name = os.getenv('DB_NAME')
    #===============================================
    os.system('aws rds describe-db-log-files --db-instance-identifier "'+ db_name +'" > log.json')
    os.system("grep 'LogFileName' log.json > lines.json")
    os.system("cat lines.json | cut -d : -f 2 | cut -d / -f 2 | cut -d , -f1 | sed 's/\"//g' >lines")
    text_file = open("lines", "r")
    files = text_file.readlines()
    print files
    text_file.close()
   # os.system("rm -rf lines")
   # os.system("rm -rf log.json")
   # os.system("rm -rf lines.json")
    #=================================================
    for file in files:
        print file
        method = 'GET'
        service = 'rds'
        region = os.getenv('REGION')
        host = 'rds.' + region + '.amazonaws.com'
        instance_name = os.getenv('DB_NAME')
        logfile = 'error/'+file.strip()
        rds_endpoint = 'https://' + host
        uri = '/v13/downloadCompleteLogFile/' + instance_name + '/' + logfile
        endpoint =  rds_endpoint + uri

        # Key derivation functions. Taken from https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
        def sign(key, msg):
            return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

        def getSignatureKey(key, dateStamp, regionName, serviceName):
            kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
            kRegion = sign(kDate, regionName)
            kService = sign(kRegion, serviceName)
            kSigning = sign(kService, 'aws4_request')
            return kSigning
        # Get session credentials
        #session = session.Session()

        #cred = session.get_credentials()

        #access_key = cred.access_key

        #secret_key = cred.secret_key
        access_key = os.getenv('AWS_ACCESS_KEY_ID')
        secret_key = os.getenv('AWS_SECRET_ACCESS_KEY') 


        if access_key is None or secret_key is None: 
            print ("Credentials are not available.")
            sys.exit()

        # Create a date for headers and the credential string
        t = datetime.datetime.utcnow()
        amzdate = t.strftime('%Y%m%dT%H%M%SZ') # Format date as YYYYMMDD'T'HHMMSS'Z'
        datestamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope

        # Overview:
        # Create a canonical request - https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
        # Sign the request.
        # Attach headers.
        # Send request

        # Create canonical URI--the part of the URI from domain to query
        canonical_uri = uri

        # Create the canonical headers
        canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amzdate + '\n'
        # signed_headers is the list of headers that are being included as part of the signing process.
        signed_headers = 'host;x-amz-date'

        # Using recommended hashing algorithm SHA-256
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'

        # Canonical query string. All parameters are sent in http header instead in this example so leave this empty.
        canonical_querystring = ''

        # Create payload hash. For GET requests, the payload is an empty string ("").
        payload_hash = hashlib.sha256(''.encode('utf-8')).hexdigest()

        # Create create canonical request
        canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

        # String to sign
        string_to_sign = algorithm + '\n' +  amzdate + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()


        # Create the signing key
        signing_key = getSignatureKey(secret_key, datestamp, region, service)

        # Sign the string_to_sign using the signing_key
        signature = hmac.new(signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256).hexdigest()

        # Add signed info to the header
        authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature
        headers = {'Accept-Encoding':'gzip', 'x-amz-date':amzdate, 'Authorization':authorization_header}

        # Send the request
        r = requests.get(endpoint, headers=headers, stream=True)

        print ("Logs Downloaded!")
        print ("Response Code: " + str(r.status_code))
        #print ("Content-Encoding: " + r.headers['content-encoding'])

        oname = 'output2.txt'
        with open(oname, 'a') as f:
            for part in r.iter_content(chunk_size=8192):
                f.write(str(part).replace(r'\n', '\n'))

        print ("Log file saved to " + oname)

    os.system("mv output2.txt logs/")
    files=["output2.txt"]    
    return files

def run_pgbadger(file_list):
    START_TIME = os.getenv('START_TIME') or \
              raiser(ValueError('START_TIME is required'))
    END_TIME = os.getenv('END_TIME') or \
              raiser(ValueError('END_TIME is required'))
    file_list = ['logs/' + f for f in file_list]
    subprocess.check_call([
        './pgbadger',
        '-j', str(psutil.cpu_count()),
        '-b', START_TIME,
        '-e', END_TIME,
        '-O', os.getcwd() + '/pg_reports',
        '-p', '%t:%r:%u@%d:[%p]:'
        ] + file_list
    )


def sync_s3(bucket, key, upload=False):
    local_path = os.getcwd() + '/pg_reports'
    s3_path = 's3://' + bucket + '/' + key
    sync_path = [s3_path, local_path]
    if upload:
        sync_path = sync_path[::-1]
    subprocess.check_call([
        'aws',
        's3',
        'sync',
        ] + sync_path
    )


def upload_to_s3(bucket, key, region):
    s3 = boto3.resource('s3', region_name=region)
    s3.Object(bucket, key).put(
        Body=open('out.html', 'rb'),
        ContentType='html',
        ACL='public-read'
        )


def get_log_states():
    global log_state
    try:
        with open('logs/status.p', 'rb') as p:
            log_state = pickle.load(p)
    except Exception:
        log_state = dict()


def save_log_states():
    with open('logs/status.p', 'wb') as p:
        pickle.dump(log_state, p)


def run():
    get_log_states()
    db_name = os.getenv('DB_NAME') or \
              raiser(ValueError('DB_NAME is required'))
    bucket = os.getenv('S3_BUCKET') or \
             raiser(ValueError('S3_BUCKET is required'))
    region = os.getenv('REGION', 'us-west-2')
    key = os.getenv('S3_KEY', 'pgbadger/')
    try:
        files = download_log_files(db_name)
        sync_s3(bucket, key)
        run_pgbadger(files)
        sync_s3(bucket, key, upload=True)
        # upload_to_s3(bucket, key, region)
    except Exception as e:
        traceback.print_exc()
    finally:
        save_log_states()


def build_schedule():
    print('Starting sqlcron. Current time: {}'
          .format(str(datetime.datetime.now())))
    interval = int(os.getenv('INTERVAL', '1'))
    unit = os.getenv('UNIT', 'day')
    time_of_day = os.getenv('TIME')

    evaluation_string = 'schedule.every(interval).' + unit
    if time_of_day:
        evaluation_string += '.at(time_of_day)'

    evaluation_string += '.do(run)'
    eval(evaluation_string)


def run_schedule():
    while True:
        sleep_time = schedule.next_run() - datetime.datetime.now()
        print('Next job to run at {}, which is {} from now'
              .format(str(schedule.next_run()), str(sleep_time)))

        # Sleep an extra second to make up for microseconds
        time.sleep(max(1, sleep_time.seconds + 1))
        schedule.run_pending()


if __name__ == "__main__":
    if not os.getenv('INTERVAL') and \
            not os.getenv('UNIT') and \
            not os.getenv('TIME'):
        run()
    elif 'now' == os.getenv('UNIT', 'none').lower():
        # Run now and exit instead of using a cron
        run()
    else:
        build_schedule()
        run_schedule()