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
    FileResponse
from security import protect_route, create_hash, check_hash

app = FastAPI()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl='login')


@app.post('/register',
          response_model=ServiceMessageResponse)
async def register(form: UserCreateForm = Depends(UserCreateForm.as_form)) -> JSONResponse:
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
async def login(form: UserLoginForm = Depends(UserLoginForm.as_form)) -> JSONResponse:
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
                       form_data: MessageForm = Depends(MessageForm.as_form)):
    with Session() as session:
        attachments = []
        for file in form_data.files:
            file_id = uuid4()
            contents = b64encode(file.file.read())
            new_file = File(id=file_id,
                            filename=file.filename,
                            mime=file.content_type,
                            contents=str(contents))
            session.add(new_file)
            session.flush()
            attachments.append(file_id)
        message = Message(id=uuid4(),
                          send_by=token['id'],
                          contents=form_data.message,
                          attachments=attachments)
        session.add(message)
        session.commit()
    return JSONResponse(None)


@app.get('/message/{id}')
@protect_route()
async def get_message(id: UUID,
                      token: Union[str, dict] = Depends(oauth2_scheme)):
    with engine.connect() as conn:
        message = conn.execute(text('select users.username, '
                                    'messages.contents, '
                                    'messages.attachments, '
                                    'messages.send_at '
                                    'from messages '
                                    'join users on messages.send_by = users.id '
                                    'where messages.id = :id'),
                               {'id': id}).mappings().one_or_none()
        attachments = text('select files.id, '
                                        'files.filename, '
                                        'files.mime, '
                                        'files.contents, '
                                        'files.created_at '
                                        'from files '
                                        'where files.id in (:attachments)')
        attachments = attachments.bindparams(bindparam('attachments', [attachment for attachment in message.attachments],
                                                       type_=ARRAY(uuid)))
        attachments = conn.execute(attachments).mappings().all()
        for attachment in attachments:
            attachment.id = str(attachment.id)
        message.attachments = attachments
        message.send_by = str(message.send_by)
        return response(MessageResponse(send_by=message.users.username,
                                        contents=message.contents,
                                        attachments=message.attachments,
                                        send_at=message.send_at))
    # attachments = []
    # for i in range(len(data['attachments'])):
    #     data['attachments'][i]['id'] = str(data['attachments'][i]['id'])
    #     data['attachments'][i]['contents'] = str(data['attachments'][i]['contents'])
    #     attachments.append(FileResponse(id=data['attachments'][i]['id'],
    #                                     filename=data['attachments'][i]['id'],
    #                                     mime=data['attachments'][i]['mime'],
    #                                     contents=data['attachments'][i]['contents'],
    #                                     created_at=data['attachments'][i]['created_at']))
    # try:
    #     return MessageResponse(send_by=data['send_by'],
    #                            contents=data['contents'],
    #                            send_at=data['send_at'],
    #                            attachments=attachments)
    # except Exception as e:
    #     print(e.__name__)


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


