import os
import uuid
from typing import Union, Annotated
import time
from datetime import timedelta, datetime

from sqlalchemy import select, and_, exc, update
from fastapi import FastAPI, Form, Depends, Request
from fastapi.security import OAuth2PasswordBearer
from werkzeug.security import generate_password_hash, check_password_hash
from jose import jwt
from psycopg import errors

from config import secret, f
from db import Session
from models import User
from pydantic_forms import UserCreate
from pydantic_responses import MessageResponse, AccessTokenResponse, UserDataResponse
from security import protect_route

app = FastAPI()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl='login')


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


@app.post('/register', response_model=MessageResponse)
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
            return MessageResponse(message='This username is unavailable.'), 422

    result = session.execute(select(User.id,
                                    User.username,
                                    User.password).where(User.username == username)).mappings().one_or_none()

    return {'id': result['id'],
            'username': result['username'],
            'password': result['password']}


@app.post('/login', response_model=Union[MessageResponse, AccessTokenResponse])
async def login(username: Annotated[str,
                Form(pattern="^[\w]{8,32}$")],
                password: Annotated[str,
                Form(pattern="^[\w]{8,64}$")]):
    session = Session()

    query = select(User.id, User.password).where(User.username == username)

    data = session.execute(query).mappings().one_or_none()

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
            session.execute(update(User).where(User.id == data['id']).values(online=True,
                                                                             last_online=datetime.utcnow()))
            session.commit()
            session.close()
            return AccessTokenResponse(access_token=auth_token)
    except ValueError:
        return MessageResponse(message='Login or password are incorrect')


@protect_route
@app.post('/user_info', response_model=Union[MessageResponse, UserDataResponse])
@protect_route
async def user_info(token: str = Depends(oauth2_scheme)):
    token = f.decrypt(token).decode(encoding='utf-8')
    try:
        token = jwt.decode(token, str(secret), algorithms='HS384')
        session = Session()
        data = session.execute(select(User.id,
                                      User.username,
                                      User.last_online,
                                      User.online).where(User.id == token['id'])).mappings().one_or_none()
    except jwt.JWTError or jwt.ExpiredSignatureError or jwt.JWTClaimsError:
        return MessageResponse(message='Token error')
    return UserDataResponse(user_id=str(data['id']),
                            username=data['username'],
                            online=data['online'],
                            last_online=data['last_online'])


# @app.post('/post_message')
# async def post_message(token: str = Depends(oauth2_scheme),
#                        message_text)
