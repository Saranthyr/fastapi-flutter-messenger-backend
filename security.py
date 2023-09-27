from functools import wraps

from jose import jwt
from sqlalchemy import select

from config import f, secret
from models import User
from pydantic_responses import MessageResponse
from db import Session


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

