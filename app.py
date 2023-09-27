import uuid
from typing import Union
import time
from datetime import timedelta, datetime
from base64 import b64encode

from sqlalchemy import select, exc, update
from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordBearer
from werkzeug.security import generate_password_hash, check_password_hash
from jose import jwt
from psycopg import errors

from config import secret, f
from db import Session
from models import User, Message, File
from pydantic_forms import UserCreateForm, UserLoginForm, MessageForm
from pydantic_responses import ServiceMessageResponse, AccessTokenResponse, UserDataResponse, MessageResponse, \
    FileResponse
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


@app.post('/register',
          response_model=ServiceMessageResponse)
async def register(form_data: UserCreateForm = Depends(UserCreateForm.as_form)):
    user_id = uuid.uuid4()
    password_hash = generate_password_hash(form_data.password, 'scrypt', 96)
    user = User(
        username=form_data.username,
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
            return ServiceMessageResponse(message='This username is unavailable.'), 422

    return ServiceMessageResponse(message='Registered'), 200


@app.post('/login',
          response_model=Union[
              ServiceMessageResponse,
              AccessTokenResponse])
async def login(form_data: UserLoginForm = Depends(UserLoginForm.as_form)):
    session = Session()

    query = select(User.id, User.password).where(User.username == form_data.username)

    data = session.execute(query).mappings().one_or_none()

    try:
        if data is None:
            raise ValueError
        elif not check_password_hash(data['password'], form_data.password):
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
        return ServiceMessageResponse(message='Login or password are incorrect')


@app.post('/user_info',
          response_model=Union[
              ServiceMessageResponse,
              UserDataResponse])
@protect_route()
async def user_info(token: str = Depends(oauth2_scheme)):
    return UserDataResponse(user_id=str(token['id']),
                            username=token['username'],
                            online=token['online'],
                            last_online=token['last_online'])


@app.post('/post_message',
          response_model=ServiceMessageResponse)
@protect_route()
async def post_message(token: str = Depends(oauth2_scheme),
                       form_data: MessageForm = Depends(MessageForm.as_form)):
    session = Session()
    attachments = []
    for file in form_data.files:
        file_id = uuid.uuid4()
        contents = b64encode(file.file.read())
        new_file = File(id=file_id,
                        filename=file.filename,
                        mime=file.content_type,
                        contents=str(contents))
        session.add(new_file)
        session.flush()
        attachments.append(file_id)
    message = Message(id=uuid.uuid4(),
                      send_by=token['id'],
                      contents=form_data.message,
                      attachments=attachments)
    session.add(message)
    session.commit()
    session.close()
    return ServiceMessageResponse(message='success')


@app.get('/message/{id}')
@protect_route()
async def get_message(id: uuid.UUID,
                      token: str = Depends(oauth2_scheme)):
    session = Session()
    data = session.execute(select(Message.send_by,
                                  Message.contents,
                                  Message.attachments).where(Message.id == id)).mappings().one_or_none()
    attachments = session.execute(select(File.id,
                                         File.filename,
                                         File.mime,
                                         File.contents).where(File.id.in_(data['attachments']))).mappings().all()
    data = dict(data)
    for i in range(len(attachments)):
        attachments[i] = dict(attachments[i])
    data['attachments'] = attachments
    data['send_by'] = str(data['send_by'])
    attachments = []
    for i in range(len(data['attachments'])):
        data['attachments'][i]['id'] = str(data['attachments'][i]['id'])
        data['attachments'][i]['contents'] = str(data['attachments'][i]['contents'])
        attachments.append(FileResponse(id=data['attachments'][i]['id'],
                                        filename=data['attachments'][i]['id'],
                                        mime=data['attachments'][i]['mime'],
                                        contents=data['attachments'][i]['contents']))
    try:
        return MessageResponse(send_by=data['send_by'],
                               contents=data['contents'],
                               attachments=attachments)
    except Exception as e:
        print(e.__name__)
