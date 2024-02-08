from uuid import uuid4, UUID
from typing import Union
import time
from datetime import timedelta, datetime
from base64 import b64encode

from sqlalchemy import select, exc, update, text, bindparam
from fastapi import FastAPI, Depends
from fastapi.encoders import jsonable_encoder
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import UUID as uuid
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Load, selectinload, defaultload, load_only
from jose import jwt
from psycopg import errors

from internals.config import secret, f
from internals.functions import response
from database import Session, engine
from database.models import User, Message, File
from pydantic_models.forms import UserCreateForm, UserLoginForm, MessageForm
from pydantic_models.responses import ServiceMessageResponse, AccessTokenResponse, UserDataResponse, MessageResponse, \
    FileResponse, MessagesResponse
from security import protect_route, create_hash, check_hash

app = FastAPI()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl='login')


@app.post('/register',
          response_model=ServiceMessageResponse)
async def register(form: UserCreateForm = Depends()) -> JSONResponse:
    user_id = uuid4()
    password_hash = create_hash(form.password)
    user = User(
        username=form.username,
        id=user_id,
        password=password_hash
    )
    with Session() as session:
        session.add(user)
        try:
            session.commit()
        except exc.IntegrityError as e:
            print(e.orig)
            session.rollback()
            return JSONResponse(jsonable_encoder(ServiceMessageResponse(message='Registered')),
                                409)

    return response(ServiceMessageResponse(message='Registered'))


@app.post('/login',
          response_model=Union[
              ServiceMessageResponse,
              AccessTokenResponse])
async def login(form: UserLoginForm = Depends()) -> JSONResponse:
    with engine.connect() as conn:
        res = conn.execute(text("select users.id, users.password "
                                "from users "
                                "where users.username = :username "
                                "limit 1"), {'username': form.username}).mappings().one_or_none()


    try:
        if res['id'] is None:
            raise ValueError
        elif check_hash(form.password, res['password']) is False:
            raise ValueError
        else:
            auth_token = jwt.encode({'id': str(res['id']),
                                     'iat': time.time(),
                                     'exp': (datetime.fromtimestamp(time.time()) + timedelta(hours=1)).timestamp(),
                                     'nbf': (datetime.fromtimestamp(time.time()) + timedelta(milliseconds=10)).
                                    timestamp()},
                                    str(secret),
                                    algorithm='HS384')
            auth_token = f.encrypt(bytes(auth_token, encoding='utf-8'))
            with engine.connect() as conn:
                conn.execute(update(User).where(User.id == res['id']).values(online=True))
                conn.commit()
            return response(AccessTokenResponse(access_token=auth_token))
    except ValueError:
        return response(ServiceMessageResponse(message='Login or password are incorrect'),
                        403)


@app.post('/user_info',
          response_model=Union[
              ServiceMessageResponse,
              UserDataResponse])
@protect_route()
async def user_info(token: Union[str, dict] = Depends(oauth2_scheme)):
    with engine.connect() as conn:
        user = conn.execute(text('select users.username, users.online, users.last_online '
                                 'from users '
                                 'where users.id = :id '
                                 'limit 1'), {'id': token['id']}).mappings().one_or_none()
    return response(UserDataResponse(user_id=str(token['id']),
                                     username=user.username,
                                     online=user.online,
                                     last_online=user.last_online))


@app.post('/post_message',
          response_model=ServiceMessageResponse)
@protect_route()
async def post_message(token: Union[str, dict] = Depends(oauth2_scheme),
                       form: MessageForm = Depends()):
    with Session() as session:
        message = Message(id=uuid4(),
                          send_by=token['id'],
                          contents=form.message)
        if form.files:
            attachments = []
            for file in form.files:
                file_id = uuid4()
                contents = b64encode(file.file.read())
                new_file = File(id=file_id,
                                filename=file.filename,
                                mime=file.content_type,
                                contents=contents.decode('utf-8'))
                session.add(new_file)
                session.flush()
                attachments.append(file_id)
            message.attachments = attachments
        session.add(message)
        try:
            session.commit()
            return response(None)
        except Exception as e:
            session.rollback()
            return response(None, 500)


@app.get('/messages')
@protect_route()
async def get_message(token: Union[str, dict] = Depends(oauth2_scheme)):
    with engine.connect() as conn:
        messages = conn.execute(text('select users.username, '
                                     'messages.contents, '
                                     'messages.attachments, '
                                     'messages.send_at '
                                     'from messages '
                                     'join users on messages.send_by = users.id '
                                     'where messages.send_by = :send_by'),
                                {'send_by': token['id']}).mappings().all()
        resp = []
        for message in messages:
            message = MessageResponse(send_by=message.username,
                                      contents=message.contents,
                                      attachments=message.attachments,
                                      send_at=message.send_at)
            resp.append(message)
        return response(MessagesResponse(messages=resp))


@app.get('/message', response_model=ServiceMessageResponse)
@protect_route()
async def get_message_latest(token: Union[str, dict] = Depends(oauth2_scheme)):
    with engine.connect() as connect:
        data = connect.execute(text(f'select message.id, user.nickname, array_length(message.attachments) '
                                    f'from messages join users on messages.send_by = users.id'
                                    f'where message.id = (select messages.id '
                                    f'from messages '
                                    f'order by messages.send_at)'))
        print(data)
    return ServiceMessageResponse(message=data['id'])


