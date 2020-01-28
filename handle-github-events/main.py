"""
GCP HTTP Cloud Function to handle github webhook events.

Some code stolen from here: https://github.com/carlos-jenkins/python-github-webhooks/blob/master/webhooks.py

"""
# -*- coding: utf-8 -*-
import hmac
import json
import datetime
import logging
import os

from ipaddress import ip_address, ip_network

import pandas as pd
import requests


def validate_request_ip(request):
    """Function to validate that request comes from a known github ip"""

    # get ip of request
    request_ip_address = ip_address(u'{}'.format(request.access_route[0]))

    # get whitelist of valid ip's from github
    github_ip_whitelist = requests.get('https://api.github.com/meta').json()['hooks']

    # check if ip is a valid one from github
    for valid_ip in github_ip_whitelist:
        if request_ip_address in ip_network(valid_ip):
            break
    else:
        error_msg = 'IP {} not allowed.'.format(request_ip_address)
        logging.error(error_msg)
        raise ValueError(error_msg)


def validate_request_signature(request):
    """Validate that request signature and function signature match"""

    # get signature from header
    sha_name, request_signature = request.headers.get('X-Hub-Signature').split('=')

    # create matching signature
    function_signature = hmac.new(
        str.encode(os.environ.get('GITHUB_WEBHOOK_SECRET', 'Specified environment variable is not set.')),
        msg=request.data,
        digestmod='sha1').hexdigest()

    # check if signatures match
    if str(request_signature) != str(function_signature):
        error_msg = 'Signatures do not match.'
        logging.error(error_msg)
        raise ValueError(error_msg)


def validate_event_type(event_type):
    """Function to error out if event type is of a type not yet implemented for handling by this function"""
    if event_type not in ['star', 'watch', 'fork']:
        error_msg = f"Event Type '{event_type}' not yet implemented by this function."
        logging.error(error_msg)
        raise NotImplementedError()


def github_event(request):
    """Function to handle incoming event from github webhook and save event data to BigQuery."""

    # validate request ip
    validate_request_ip(request)

    # validate request signature
    validate_request_signature(request)

    # request_timestamp
    request_timestamp = str(datetime.datetime.now())

    # github_request_type
    github_event_type = request.headers.get('X-GitHub-Event')
    validate_event_type(github_event_type)

    # get relevant env vars
    gcp_project_id = os.environ.get('GCP_PROJECT_NAME')
    bq_dataset_name = os.environ.get('BQ_DATASET_NAME')
    bq_table_name = os.environ.get('BQ_TABLE_NAME')
    bq_if_exists = os.environ.get('BQ_IF_EXISTS')
    bq_table_suffix = request_timestamp.replace('-', '')[0:8]

    # get json from request
    request_json = request.get_json()

    # create response body
    response_body = {
        "request_method": str(request.method),
        "timestamp": request_timestamp,
        "event_type": github_event_type,
        "action": request_json.get("action", github_event_type),
        "starred_at": request_json.get("starred_at", ""),
        "repository_full_name": request_json.get("repository")["full_name"],
        "sender_username": request_json.get("sender")["login"]
    }

    # build response
    response = {
        "statusCode": 200,
        "body": response_body
    }

    # logging response
    logging.info(response)

    # make pandas df
    data = [response_body['timestamp'], response_body['repository_full_name'], response_body['event_type'],
            response_body['action'], response_body['sender_username']]
    columns = ['timestamp', 'repo', 'event_type', 'action', 'username']
    df = pd.DataFrame(data=[data], columns=columns)

    # display df.head() in logs
    logging.info(df.head())

    # save to big query
    df.to_gbq(
        destination_table=f'{bq_dataset_name}.{bq_table_name}_{bq_table_suffix}',
        project_id=gcp_project_id, if_exists=bq_if_exists
    )

    return json.dumps(response, indent=4)
