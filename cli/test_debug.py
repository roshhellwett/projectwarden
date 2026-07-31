import subprocess, json, struct, time

p = subprocess.Popen(['python', '-m', 'zenith_passkeys.native_host.host'], cwd=r'a:\projectwarden\cli\src', stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

b = json.dumps({'action': 'unlock', 'password': '3330', 'requestId': '1'}).encode('utf-8')
p.stdin.write(struct.pack('=I', len(b)) + b)
p.stdin.flush()

len_bytes = p.stdout.read(4)
print('Len bytes:', len_bytes)
if len_bytes:
    l = struct.unpack('=I', len_bytes)[0]
    print('Stdout:', p.stdout.read(l).decode('utf-8'))

b2 = json.dumps({'action': 'list_credentials', 'requestId': '2'}).encode('utf-8')
p.stdin.write(struct.pack('=I', len(b2)) + b2)
p.stdin.flush()
len_bytes = p.stdout.read(4)
print('Len bytes 2:', len_bytes)
if len_bytes:
    l = struct.unpack('=I', len_bytes)[0]
    print('Stdout 2:', p.stdout.read(l).decode('utf-8'))

print('Stderr:', p.stderr.read().decode())
