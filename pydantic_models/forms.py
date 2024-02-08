import logging
from dataclasses import dataclass
from typing import List, Union
from typing_extensions import Annotated

from pydantic import BaseModel, field_validator
from fastapi import Form, File, UploadFile


@dataclass
class UserCreateForm:
    username: str = Form(...)
    password: str = Form(...)


@dataclass
class UserLoginForm(UserCreateForm):
    pass


@dataclass
class MessageForm:
    message: str = Form(...)
    files: Union[List[UploadFile], None] = File(None)
