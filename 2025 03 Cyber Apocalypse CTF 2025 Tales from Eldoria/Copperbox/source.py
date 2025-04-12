import secrets

p = 0x31337313373133731337313373133731337313373133731337313373133732ad
a = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
b = 0xdeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0de

def lcg(x, a, b):
    while True:
        yield (x := a*x + b)

flag = open('flag.txt', 'rb').read()
x = int.from_bytes(flag + secrets.token_bytes(30-len(flag)), 'big')
gen = lcg(x, a, b)

h1 = next(gen) * pow(next(gen), -1, p) % p
h2 = next(gen) * pow(next(gen), -1, p) % p

with open('output.txt', 'w') as o:
    trunc = 48
    # oops, i forgot the last part
    o.write(f'hint1 = {h1 >> trunc}\n')
    o.write(f'hint2 = {h2 >> trunc}\n')