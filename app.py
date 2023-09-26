import os
import uuid
from typing import Union, Annotated
from base64 import b64encode
import time
from datetime import timedelta, datetime

from dotenv import load_dotenv
from sqlalchemy import create_engine, select, and_, exc
from sqlalchemy.orm import sessionmaker
from fastapi import FastAPI, Form, Depends, Request
from werkzeug.security import generate_password_hash, check_password_hash
from jose import jwt
from cryptography.fernet import Fernet
from psycopg import errors

from models import User
from pydantic_forms import UserCreate
from pydantic_responses import MessageResponse

app = FastAPI()
load_dotenv()

engine = create_engine(f'postgresql+psycopg://{os.environ["DB_USER"]}:{os.environ["DB_PASSWORD"]}@'
                       f'{os.environ["DB_HOST"]}:{os.environ["DB_PORT"]}/{os.environ["DB_NAME"]}')
Session = sessionmaker(engine, autoflush=False)

secret = b'A\xa3\x8c\x9a>\x96\xd6njF\x8a%j\x9bil\xfe\x8aq\xd6\xe8\x87\xfe:\xea\xf7\x18q\xc3\xaeK\x88\xe0\x91\xae\x85\
xcd\xcf\xd0q:\xb1\xf3\xb5\x16\x164\xe3"/\x10_\xb5\xff\x8c\xae\x85\x86\xc8\xdbI)\x98['
secret = b64encode(secret)
key = Fernet.generate_key()
f = Fernet(key)


@app.get('/')
async def root():
    """
    Root route
    :return: simple string
    """

    return 'Nothing to look at \'ere'


# @app.get('/{number}')
# async def numbers(number: int):
#     """
#     simple integer path param
#     :param number: int
#     :return: string containing set number
#     """
#     return f'Path contains {number}'

@app.get('/{number}')
async def even_odd(number: Union[int, float]):
    """

    :param number:
    :return:
    """

    match number % 2:
        case 1:
            return f'Number {number} is odd'
        case 0:
            return f'Number {number} is even'
        case _:
            return f'Number {number} is not int'


@app.post('/register')
async def register(username: Annotated[str,
                   Form(pattern="^[\w]{8,32}$")],
                   password: Annotated[str,
                   Form(pattern="^[\w]{8,64}$")]):
    user_id = uuid.uuid4()
    password_hash = generate_password_hash(password, 'scrypt', 96)
    user = User(
        username=username,
        id=user_id,
        password=password_hash
    )
    with Session() as session:
        session.add(user)
        try:
            session.commit()
        except exc.IntegrityError as e:
            assert isinstance(e.orig, errors.UniqueViolation)
            session.rollback()
            return {'message': 'This username is unavailable.'}, 422

    result = session.execute(select(User.id,
                                    User.username,
                                    User.password).where(User.username == username)).mappings().one_or_none()

    return {'id': result['id'],
            'username': result['username'],
            'password': result['password']}


@app.post('/login')
async def login(username: Annotated[str,
                Form(pattern="^[\w]{8,32}$")],
                password: Annotated[str,
                Form(pattern="^[\w]{8,64}$")]):
    session = Session()

    query = session.execute(select(User.id, User.password).where(User.username == username)).mappings()

    data = query.one_or_none()

    try:
        if data is None:
            raise ValueError
        elif not check_password_hash(data['password'], password):
            raise ValueError
        else:
            auth_token = jwt.encode({'id': str(data['id']),
                                     'iat': time.time(),
                                     'exp': (datetime.fromtimestamp(time.time()) + timedelta(hours=1)).timestamp(),
                                     'nbf': (datetime.fromtimestamp(time.time()) + timedelta(milliseconds=10)).
                                    timestamp()},
                                    str(secret),
                                    algorithm='HS384')
            auth_token = f.encrypt(bytes(auth_token, encoding='utf-8'))
            return {'token': auth_token}
    except ValueError:
        return {'message': 'Login or password are incorrect'}
