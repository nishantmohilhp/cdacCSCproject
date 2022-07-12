import k9
 
try:
    k9.sniffing('en0')
 
except KeyboardInterrupt:
    print('Exit...')
