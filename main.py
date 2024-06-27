#!/usr/bin/python3
from psycopg2 import connect
from dotenv import load_dotenv
from os import environ
from tqdm import tqdm

load_dotenv()

DB = environ.get("DB")
DB_USER = environ.get("DB_USER")
DB_PASSWORD = environ.get("DB_PASSWORD")
DB_HOST = environ.get("DB_HOST")

GET_HOSTS = '''
select de.host as c from dojo_finding df 
	left join dojo_endpoint_status des on df.id = des.finding_id 
	left join dojo_endpoint de on de.id = des.endpoint_id
	where 
	df.active != false and verified != false
	group by df.hash_code, de.host 
	having count(df.hash_code) > 1
	order by df.hash_code, df.hash_code
'''

GET_VULNS = '''
select df.id, df.title, df.hash_code, df.created,  df.severity, df.test_id, df.date, df.created, df.hash_code
from dojo_finding df 
	left join dojo_endpoint_status des on df.id = des.finding_id 
	left join dojo_endpoint de on de.id = des.endpoint_id
	where de.host = '{}' and 
    df.active != false and verified != false
	order by df.hash_code, df.created;
'''

SET_DUPLICATES = '''
UPDATE dojo_finding set active = False, verified = False, duplicate = True where id in ({}) RETURNING id
'''

HOSTS = []
cnt = 1
max = 2

HASH_CODE = 2
CREATED = 3
SKIP_REMOVE = False

def check_if_hash_exists(hash, buffer):
  for el in buffer:
    if el[2] == hash:
      return True
  return False


def make_dedup(dedup_list):
    new_buffer = []
    for idx, old_buffer in enumerate(dedup_list):
        hash = old_buffer[HASH_CODE]
        if not check_if_hash_exists(hash, new_buffer):
            new_buffer.append(old_buffer)
            dedup_list.pop(idx)
    return dedup_list

def make_request(conn, request):
    with conn.cursor() as cursor:
        try:
            cursor.execute(request)
            records = cursor.fetchall()
        except Exception as e:
            print('- Error make_request: ' + str(e))
            records = None
        return records

def dedup_init():
    with connect(dbname=DB, user=DB_USER, password=DB_PASSWORD, host=DB_HOST) as conn:
        need_dedup = []
        remove_ids = []
        print('+ Запрашиваем данные по уязвимым хостам')
        max_items_pre_request = 5 #fix problem execute more items per one request in UPDATE
        all_items_pre_request = 0
        cnt = 0
        hosts = make_request(conn, GET_HOSTS)
        for el in tqdm(hosts):
            host = el[0]
            vulners = make_request(conn, GET_VULNS.format(host))
            if len(list(vulners)) > 0:
                     remove_list = make_dedup(list(vulners))
                     all_items_pre_request = len(remove_list)
            if SKIP_REMOVE:
                print('------Duplicates for host: {}----------------'.format(host))
                for vul in vulners:
                    print(vul)
                continue
            if all_items_pre_request > 0: #all find problems
                for idx, el in enumerate(remove_list):
                     cnt += 1 #total write in db
                     remove_ids.append(str(el[0])) #temp buffer for remove
                     if len(remove_ids) >= max_items_pre_request or all_items_pre_request == cnt:
                         ids_string = ', '.join(remove_ids)
                         #print('Will disable {} vulnarabilities'.format(cnt))
                         #print(SET_DUPLICATES.format(ids_string))

                         dedupe_activity = make_request(conn, SET_DUPLICATES.format(ids_string))
                         #print('[{}] Updated values: {}'.format(host, list(dedupe_activity)))
                         remove_ids.clear()
        print('+ Finish: remove {} duplicates.'.format(cnt))

if __name__ == "__main__":
    dedup_init()