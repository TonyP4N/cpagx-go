"""Atomic Redis capacity admission. Redis failure rejects instead of bypassing."""
SCRIPT = '''
if redis.call('SISMEMBER', KEYS[1], ARGV[1]) == 1 then return -1 end
if redis.call('SCARD', KEYS[1]) >= tonumber(ARGV[2]) then return 0 end
redis.call('SADD', KEYS[1], ARGV[1])
redis.call('EXPIRE', KEYS[1], ARGV[3])
return 1
'''

class DuplicateActive(RuntimeError):
    pass

def acquire(client, task_id, limit):
    if client is None:
        raise RuntimeError('Redis concurrency service unavailable')
    admitted = client.eval(SCRIPT, 1, 'v2_active_tasks', task_id, limit, 7200)
    if admitted == -1:
        raise DuplicateActive('Task already executing')
    if not admitted:
        raise RuntimeError('Too many concurrent tasks or duplicate active task')

def release(client, task_id):
    client.srem('v2_active_tasks', task_id)
