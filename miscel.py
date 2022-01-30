import string
import random as r


def generating_secret_key():
    random_ascii = [r.choice(string.ascii_letters) for i in range(20)] + [r.choice(string.digits) for i in
                                                                          range(15)]
    new_random_ascii = ''.join(random_ascii)
    return new_random_ascii


print(generating_secret_key())
