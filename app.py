import os
import uuid
from typing import Union, Annotated
from dotenv import load_dotenv
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from fastapi import FastAPI, Form, Depends, Request
from models import User
from pydantic_forms import UserCreate

app = FastAPI()
load_dotenv()

engine = create_engine(f'postgresql+psycopg://{os.environ["DB_USER"]}:{os.environ["DB_PASSWORD"]}@'
                     f'{os.environ["DB_HOST"]}:{os.environ["DB_PORT"]}/{os.environ["DB_NAME"]}')
Session = sessionmaker(engine)


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
async def register(username: Annotated[str, Form(pattern="^[a-zA-Z_]{8,32}$")]):
    user_id = uuid.uuid4()
    user = User(
        username=username,
        id=user_id
    )
    with Session() as session:
        session.add(user)
        session.commit()

    return {'user_id': session.execute(select(User.id).where(User.username == username)).one_or_none()[0],
            'username': username}
