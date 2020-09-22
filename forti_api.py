import requests
import settings
import json
import datetime
import bottle
import redis
import logging

app = application = bottle.default_app()
logger = logging.getLogger("forti_api")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler = logging.FileHandler("/var/log/forti_api.log")
handler.setFormatter(formatter)
logger.addHandler(handler)

debug = False

def apicheck(fn):
  def _wrap(*args, **kwargs):
    try:
      provided_api_key = bottle.request.headers['api-key']
    except:
      provided_api_key = ''
    try:
      for api_key in settings.api_keys:
        if provided_api_key == api_key['api-key']:
          if bottle.request.path in api_key['allowed']:
            logger.info('api-key user: {} logged: {}, remote ip: {}'.format(api_key['username'], bottle.request.path, bottle.request.environ.get('REMOTE_ADDR')))
            return fn(*args, **kwargs)
        if bottle.request.environ.get('REMOTE_ADDR') in api_key['whitelist']:
          if bottle.request.path in api_key['allowed']:
            logger.info('whitelisted user: {} logged: {}, remote ip: {}'.format(api_key['username'], bottle.request.path, bottle.request.environ.get('REMOTE_ADDR')))
            return fn(*args, **kwargs)
    except Exception as e:
      logger.info('Exception was: {}'.format(e))
      bottle.response.status = 401
      return {"result":"failed","message":"Something went wrong, exiting..."}
     
    logger.info('{} api auth failed for {}'.format(bottle.request.path, bottle.request.environ.get('HTTP_X_FORWARDED_FOR')))
    bottle.response.status = 401
    return {"result":"failed","message":"api-key is not valid here"}
  return _wrap


def update_redis(key, db=0, data=datetime.datetime.now().strftime("%Y-%b-%d %H:%M")):
  r = redis.StrictRedis(settings.redis_host, port=6379, db=db, password=settings.redis_auth)
  h = r.set(key, data)
  return h


def get_addressgroup(group_name):
  headers = {'Authorization': 'Bearer {}'.format(settings.access_token) }
  url = 'http://{}/api/v2/cmdb/firewall/addrgrp/{}'.format(settings.fw['fqdn'], group_name)
  params = {'vdom':settings.vdom}
  r = requests.get(url, headers=headers, params=params, verify=False)
  if len(r.json()['results']) > 1:
      return False
  return r.json()['results'][0]['member']


def create_address(name, subnet):
  headers = {'Authorization': 'Bearer {}'.format(settings.access_token) }
  url = 'https://{}/api/v2/cmdb/firewall/address'.format(settings.fw['fqdn'])
  params = {'vdom':settings.vdom}
  comment = 'Added: {}'.format(datetime.datetime.now().strftime("%Y-%b-%d %H:%M"))
  data = {"name":name, "subnet":subnet, "comment":comment}
  r = requests.post(url, headers=headers, json=data, params=params, verify=False)
  ''' status_code is 500 if address objecy already exists...  '''
  return True
  

def add_to_addressgroup(group_name, members, new_member):
  l = []
  headers = {'Authorization': 'Bearer {}'.format(settings.access_token) }
  url = 'https://{}/api/v2/cmdb/firewall/addrgrp/{}'.format(settings.fw['fqdn'], group_name)
  params = {'vdom':settings.vdom}
  for member in members:
    d = {"name":member['name']}
    l.append(d)
  d = {"name":new_member}
  l.append(d)
  data = {"member":l}
  r = requests.put(url, headers=headers, json=data, params=params, verify=False)
  print(r.text)
  print(r.status_code)
  return True


@bottle.get('/forti_api/v1/auth')
@apicheck
def auth():
    return {'status_code':200, 'message':'apicheck passed'}


@bottle.get('/forti_api/v1/ipv4list')
def ipv4list():
    r = redis.StrictRedis(settings.redis_host, port=6379, db=1, password=settings.redis_auth)
    pattern = '*'
    bottle.response.status = 200
    return bottle.template('ip_list.html', blocklist=r.keys(pattern))


@bottle.post('/forti_api/v1/redis_blocklist')
@apicheck
def redis_blocklist():
  try:
    byte = bottle.request.body
    data = json.loads(byte.read().decode('UTF-8'))
    if debug:
      logger.info(data)
  except Exception as e:
    logger.exception('Failed to read body')
    bottle.response.status = 400
    return {'status':400, 'message':'Wrong input parameters'}

  if data['event_definition_id'] == 'this-is-a-test-notification':
    bottle.response.status = 201
    return 

  try:
    ssh_invalid_user_ip = data['backlog'][0]['fields']['ssh_invalid_user_ip']
  except:
    logger.debug('Failed to read input parameters')
    bottle.response.status = 400
    return {'status':400, 'message':'Wrong input parameters'}

  try:
    update_redis(ssh_invalid_user_ip, db=settings.redis_index)
    logger.debug('Added {} to redis'.format(ssh_invalid_user_ip,))
  except:
    logger.exception('Failed to add IP to redis...')
    bottle.response.status = 500
    return {'status_code':500, 'message':'Failed to add ip to redis'}

  bottle.response.status = 200
  return {'status_code':200, 'message':'Successfully added ip to redis'}


@bottle.post('/forti_api/v1/autoban')
@apicheck
def autoban():
  try:
    byte = bottle.request.body
    data = json.loads(byte.read().decode('UTF-8'))
    if debug:
      logger.info(data)
  except Exception as e:
    logger.exception('Failed to read body')
    bottle.response.status = 400
    return {'status':400, 'message':'Wrong input parameters'}

  if data['event_definition_id'] == 'this-is-a-test-notification':
    bottle.response.status = 201
    return

  try:
    ssh_invalid_user_ip = data['backlog'][0]['fields']['ssh_invalid_user_ip']
  except:
    logger.debug('Failed to read input parameters')
    bottle.response.status = 400
    return {'status':400, 'message':'Wrong input parameters'}

  address_name = 'auto-{}'.format(ssh_invalid_user_ip)
  subnet = '{}/32'.format(ssh_invalid_user_ip)
  addressgroup_name = 'MaliciousAuto'
  try:
    create_address(address_name, subnet)
    members = get_addressgroup(addressgroup_name)
    add_to_addressgroup(addressgroup_name, members, address_name)
  except:
    logger.exception('Something failed when trying to communicate with the fortigate')
    bottle.response.status = 500
    return {'status':500, 'message':'Failed to communicate with the firewall'}

  return {'status_code':200, 'message':'Successfully uppdated address group'}


if __name__ == '__main__':
  bottle.run(host='0.0.0.0', port=8080, debug=True, reloader=True)
  
