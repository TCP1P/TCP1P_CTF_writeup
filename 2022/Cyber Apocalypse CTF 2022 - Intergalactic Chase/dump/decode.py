from pwn import *
import os, subprocess, sys




#os.environ['PYTHONUNBUFFERED'] = "1"
proc = subprocess.Popen(
    ['/usr/bin/python3', 'source.py'],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    )

sleep(0.5)

dec = 'Initialization Sequence - Code 0'
sequence = ''
key = ''
#print(range(len(dec)))

while sequence != dec:
    for j in range(len(dec)):
#        if j == 3-1:
#            key += '00 '
#            continue
        for i in range(256):
            with remote('0.0.0.0', 1337) as p:
                # hide pwn debug message
                context.log_level = 'CRITICAL'

                # sending
                p.recv(255).decode()
                p.sendline(b'0')
                p.recv(255).decode()
                
                
                encrypted_key = key + '{:02x}'.format(i) + ' ' + '00 ' * (len(dec)-(j+1))
                print(encrypted_key)
                #print(len(encrypted_key))
                p.sendline(bytes(f'{encrypted_key}', 'latin1'))
                
                data = p.recv(b'100').decode()
                #sleep(1)
                #print(data)
                sequence = data.replace('\nsequence:\n', '')
                #print(sequence)
                if sequence[j] == dec[j]:
                    key += '{:02x} '.format(i)
                    break
        print(key)
                
# send signal to quit
proc.send_signal(9)