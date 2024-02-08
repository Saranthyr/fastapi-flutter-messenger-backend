import os
from functools import wraps
from hashlib import scrypt
from base64 import b64encode, b64decode

from jose import jwt
from sqlalchemy import select

from internals.config import f, secret
from database import Session
from database.models import User


def protect_route():
    def wrapper(func):
        @wraps(func)
        async def wrapped(*args, **kwargs):
            token = f.decrypt(kwargs.get('token')).decode(encoding='utf-8')
            try:
                token = jwt.decode(token, str(secret), algorithms='HS384')
            except jwt.JWTError or jwt.ExpiredSignatureError or jwt.JWTClaimsError:
                raise Exception
            session = Session()
            data = session.execute(select(User.id,
                                          User.username,
                                          User.last_online,
                                          User.online).where(User.id == token['id'])).mappings().one_or_none()
            if data is None:
                raise Exception
            else:
                kwargs['token'] = data
                return await func(*args, **kwargs)

        return wrapped

    return wrapper


def create_hash(password: str):
    salt = os.urandom(32)
    password = scrypt(b64decode(password),
                      n=16384,
                      r=8,
                      p=1,
                      salt=salt,
                      maxmem=0,
                      dklen=64)
    password = f'{b64encode(salt).decode("utf-8")}$' \
               f'{b64encode(password).decode("utf-8")}'
    return password


def check_hash(password: str, hashed: str):
    salt, hashed = hashed.split('$')
    password = b64encode(scrypt(b64decode(password),
                                n=16384,
                                r=8,
                                p=1,
                                salt=b64decode(salt),
                                maxmem=0,
                                dklen=64)).decode('utf-8')
    if password == hashed:
        return True
    else:
        return False

