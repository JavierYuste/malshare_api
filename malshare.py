import argparse
import logging
import requests
import sys
import json
import shutil
import datetime
from random import uniform
from time import sleep
import os

logging.basicConfig(format='%(asctime)s [%(levelname)s]: %(message)s', datefmt='%m/%d %I:%M:%S', level=logging.INFO)

parser = argparse.ArgumentParser()
parser.add_argument('-k', '--api-key', help='API key', type=str,
                    default='API.key')
parser.add_argument('-o', '--output-folder', help='Output folder', type=str, default='samples')
parser.add_argument('-d', '--first-date', help='Download samples uploaded from this date to today', type=str, default='2019-10-29')

def get_sample(hash):
    try:
        logging.info("Downloading sample from SHA256: {}".format(str(hash)))
        req = requests.get("https://malshare.com/api.php?api_key={}&action=getfile&hash={}".format(api_key, str(hash)),
                           stream=True)
        if req.status_code == 200:
            with open('{}/{}'.format(str(args.output_folder), str(hash)), 'wb') as output_file:
                shutil.copyfileobj(req.raw, output_file)
            del req
        else:
            return None
    except Exception as e:
        logging.exception('An exception occurred while downloading sample ' + str(hash))
        logging.error(e, exc_info=True)
        return None

def get_details(hash):
    try:
        req = requests.get("https://malshare.com/api.php?api_key={}&action=details&hash={}".format(api_key, str(hash)))
        if req.status_code == 200:
            details = json.loads(req.content)
            return details
        else:
            return None
    except Exception as e:
        logging.exception('An exception occurred while requesting details for {}'.format(str(hash)))
        logging.error(e, exc_info=True)
        return None

def is_PE(hash):
    try:
        details = get_details(hash)
        if 'F_TYPE' in details:
            logging.info("Requested file is of type {}".format(details['F_TYPE']))
            return details['F_TYPE'] == 'PE32'
        else:
            logging.error("Requested file ({}) does not report a type at all!".format(str(hash)))
            return True
    except Exception as e:
        logging.exception('An exception occurred while requesting details for {}'.format(str(hash)))
        logging.error(e, exc_info=True)
        return True

def get_limit_api():
    try:
        req = requests.get("https://malshare.com/api.php?api_key={}&action=getlimit".format(api_key))
        if req.status_code == 200:
            limits = json.loads(req.content)
            logging.info("Remaining calls: {}".format(str(limits['REMAINING'])))
            return limits
        else:
            return None
    except Exception as e:
        logging.exception('An exception occurred while requesting API limit')
        logging.error(e, exc_info=True)
        return None

def get_next_date(date):
    date = str(date)
    date_res = date.split('-')
    now = datetime.datetime.now()
    if int(date_res[2]) == int(now.day) and int(date_res[1]) == int(now.month) and int(date_res[0]) == int(now.year):
        # Today
        logging.debug("Today reached!")
        return None
    elif int(date_res[2]) >= 31 and int(date_res[1]) >= 12:
        date_res[2] = '1'
        date_res[1] = '1'
        date_res[0] = str(int(date_res[0]) + 1)
    elif int(date_res[2]) >= 31:
        date_res[2] = '1'
        date_res[1] = str(int(date_res[1]) + 1)
    else:
        date_res[2] = str(int(date_res[2]) + 1)
    date_res = date_res[0] + '-' + date_res[1] + '-' + date_res[2]
    logging.debug("Returning date {}".format(date_res))
    return date_res

def exists_hash(directory, sha256):
    for file in os.listdir(directory):
        if file == sha256:
            return True
    return False

def get_hashes_from_date(date, output=None):
    try:
        logging.info("Retrieving hashes from date {}".format(str(date)))
        req = requests.get("https://malshare.com/daily/{}/malshare_fileList.{}.sha256.txt".format(str(date), str(date)))
        if req.status_code == 200:
            hashes = []
            for hash in req.content.splitlines():
                hashes.append(str(hash))
            return hashes
        else:
            return None
    except Exception as e:
        logging.exception('An exception occurred while getting hashes from date {}'.format(str(date)))
        logging.error(e, exc_info=True)
        return None

if __name__ == '__main__':
    args = parser.parse_args()
    global api_key
    if args.api_key is None:
        logging.error("No API key provided")
    else:
        try:
            with open(args.api_key, 'r') as f:
                api_key = str(f.readline())
        except Exception as e:
            logging.exception('An exception occurred while reading API key from ' + str(f))
            logging.error(e, exc_info=True)
            sys.exit(1)

    if api_key is None or len(api_key) != 64:
        logging.exception('Not a valid API key')
        sys.exit(1)

    # TODO: check error on date
    date = args.first_date
    with open('last', 'w') as f:
        f.write(str(date))
    limit = int(get_limit_api()['REMAINING'])
    while limit is not None and limit > 2 and date is not None:
        limit = limit - 1
        hashes = get_hashes_from_date(date)
        for hash_ in hashes:
            if not exists_hash(args.output_folder, hash_):
                if limit < 3:
                    logging.info("Sleeping 24 hours... zzz")
                    sleep(60*60*24)
                    limit = int(get_limit_api()['REMAINING'])
                sleep(uniform(0, 1.5))
                limit = limit - 1
                if limit > 1 and is_PE(hash_[2:-1]):
                    limit = limit - 1
                    get_sample(hash_[2:-1])
            else:
                logging.info("Hash already obtained!")
        date = get_next_date(date)
        with open('last', 'w') as f:
            f.write(str(date))
        limit = int(get_limit_api()['REMAINING'])
    logging.info("Exiting...")