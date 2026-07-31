
import sys
import traceback

def log(msg):
    with open('C:/Users/roshh/AppData/Roaming/zenith-passkeys/host_debug.log', 'a') as f:
        f.write(msg + '\n')

try:
    log('Starting host...')
    from zenith_passkeys.native_host.host import NativeHost
    host = NativeHost()
    log('Host initialized.')
    host.run()
except Exception as e:
    log('Fatal exception:\n' + traceback.format_exc())
