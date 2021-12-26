from hashlib import sha256
from string import printable

print('begin...')
data = 'reeLU'
for x in printable:
    for y in  printable:
        for z in printable:
            for a in printable:
                tmp = data + x + y + z + a
                res = sha256(tmp.encode()).hexdigest()
                if res[:8] == '00000000':
                    print(tmp)
                    print(res)
                    print('=' * 50)
print('end...')