import requests
import json
import os.path

from bitcoin_rpc_config import rpc_auth, rpc_host, rpc_port

if not rpc_host:
    raise Exception('Please set rpc_auth, rpc_host and rpc_port in bitcoin_rpc.py.')

def bitcoin_rpc(method, params=None, id=None):
    assert isinstance(method, str)
    data = json.dumps({
        'jsonrpc': '1.0',
        'id': id or '0',
        'method': method,
        'params': params or []
    })
    return requests.post(
        'http://{}:{}'.format(rpc_host, rpc_port),
        auth=rpc_auth, data=data).json().get('result')


#print(json.dumps(bitcoin_rpc('getblock', ['0cab8c11bf0d876ba68c174a66e17b29170dc86faf01cba4b140bda75fcd386a']), indent=2))
#print(json.dumps(bitcoin_rpc('getchaintips'), indent=2))

