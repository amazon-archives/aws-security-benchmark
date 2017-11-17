#!/usr/bin/python3
#from jsonpath_rw import jsonpath, parse
from __future__ import print_function

import sys
import os
import json
import urllib
import boto3
import re

print('Loading function')

s3 = boto3.client('s3')


from collections import OrderedDict
from jsonpath_ng import jsonpath, parse

import datetime

# Our imports
from elasticsearch import Elasticsearch, ElasticsearchException, RequestsHttpConnection
from requests_aws4auth import AWS4Auth


# default index to use
ES_INDEX = "aws-cis-metrics-%Y-%m-%d"
ES_URL = None
ES_USERNAME=None
ES_PASSWORD=None
# can be one of iam, http or none
ES_AUTHMETHOD="iam"

tsnow = datetime.datetime.utcnow()


def processreport(contents, accountId):
    global ES_AUTHMETHOD

    print("processing report")

    myfilejson=json.loads(contents)

    jsonpath_expr = parse('"*"."*"')

    convjson=[(str(match.path), match.value) for match in jsonpath_expr.find(myfilejson)]

    
    ES_AUTHMETHOD = os.environ.get("es_authmethod", ES_AUTHMETHOD)

    try:
       
        if ES_AUTHMETHOD=="iam": 
            connection_class=RequestsHttpConnection
            awsauth = AWS4Auth(os.environ.get("AWS_ACCESS_KEY_ID", None), os.environ.get("AWS_SECRET_ACCESS_KEY", None), os.environ.get("AWS_REGION", None), 'es', session_token=os.environ.get("AWS_SESSION_TOKEN", None))
            es = Elasticsearch(hosts=[ES_URL], verify_certs=True, use_ssl=True, ca_certs='/etc/ssl/certs/ca-bundle.crt', http_auth=awsauth, connection_class=RequestsHttpConnection)
        # send http auth if user is specified
        elif ES_AUTHMETHOD=="http":
           if ES_USERNAME:
               es = Elasticsearch(hosts=[ES_URL], verify_certs=True, use_ssl=True, ca_certs='/etc/ssl/certs/ca-bundle.crt', http_auth=(ES_USERNAME, ES_PASSWORD))
           else:
               es = Elasticsearch(hosts=[ES_URL], verify_certs=True, use_ssl=True, ca_certs='/etc/ssl/certs/ca-bundle.crt')
        else:
           es = Elasticsearch(hosts=[ES_URL], verify_certs=True, use_ssl=True, ca_certs='/etc/ssl/certs/ca-bundle.crt')
            
        today = datetime.datetime.today()
        myesindex=today.strftime(ES_INDEX)
        print('Creating es index: '+myesindex)
        es.indices.create(index=myesindex,
            ignore=[400],
            body={'mappings':{'aws-cis-metric':
            {'properties':
            {'@timestamp':{'type':'date'},
            'ControlId':{'type':'string'},
            'AccountId': {'type':'string'},
            'ScoredControl':{'type':'boolean'},
            'Offenders': {'type':'array'},
            'failReason': {'type':'string'},
            'Description': {'type':'string'},
            'Result': {'type': 'boolean'},
            }
            }
            }})
    except ElasticsearchException as error:
        sys.stderr.write("Can't connect to Elasticsearch server %s: %s, continuing.\n" % (ES_URL, str(error)))
        exit(1)

# Assemble all metrics into a single document
# Use @-prefixed keys for metadata not coming in from PCP metrics
    es_doc = OrderedDict({'@timestamp': today})

    try:
        for t,v in convjson:
            d=OrderedDict()
            for v1 in v.items():
                d[v1[0]] = v1[1]
                d['AccountId']=accountId

# pylint: disable=unexpected-keyword-arg
            es.index(index=myesindex,
                    doc_type='aws-cis-metric',
                    timestamp=tsnow,
                    body=OrderedDict(list(es_doc.items())+list(d.items())))
    except ElasticsearchException as error:
        sys.stderr.write("Can't send to Elasticsearch server %s: %s, continuing.\n" % (ES_URL, str(error)))
        exit(1)


def lambda_handler(event, context):
    global ES_URL
    global ES_INDEX
    global ES_USERNAME
    global ES_PASSWORD
    global ES_AUTHMETHOD
    print("invoked lambda handler")

    b64pattern = re.compile("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$")
    from base64 import b64decode

    ES_URL=os.environ.get("es_url", None)
    ES_INDEX=os.environ.get("es_index", ES_INDEX)
    ES_USERNAME = os.environ.get("es_username", None)
    ES_PASSWORD = os.environ.get("es_password", None)
    ES_ENCVAR = os.environ.get("es_encenvvar", None)

    if ES_URL:
        print("Using es server: " + ES_URL)
    else:
        print("Failed to obtain ES_URL, please set environment variables")
        exit(1)
    if ES_INDEX :
        print("Using es index: " + ES_INDEX)


    # Decrypt code should run once and variables stored outside of the function
    # handler so that these are decrypted once per container
    if ES_USERNAME and ES_ENCENVVAR:
        if b64pattern.match(ES_USERNAME):
            print("Decryting es_username")
            ES_USERNAME= boto3.client('kms').decrypt(CiphertextBlob=b64decode(ES_USERNAME))['Plaintext']

    if ES_PASSWORD and ES_ENCENVVAR:
        if b64pattern.match(ES_PASSWORD):
            print("Decryting es_password")
            ES_PASSWORD= boto3.client('kms').decrypt(CiphertextBlob=b64decode(ES_PASSWORD))['Plaintext']

    # Get the object from the event and show its content type
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.parse.unquote(event['Records'][0]['s3']['object']['key'])
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        #print("CONTENT TYPE: " + response['ContentType']+"\n")
        print("KEY: " + key+"\n")
        matchObj = re.match('cis_report_([0-9]+)_.*\.json', key, flags=0)
        if matchObj:
            accountId=matchObj.group(1)
            print("Received report for " + key + " Account: "+accountId)
        else:
            print("KEY: " + key + " does not look like a report file, ignoring")

        contents = response['Body'].read()
        processreport(contents, accountId) 
        print("finished processing report")
        return "Processed report " + key
    except Exception as e:
        print(e)
        print('Error getting object {} from bucket {}. Make sure they exist and your bucket is in the same region as this function.'.format(key, bucket))
        raise e

