from typing import List

from pydantic import BaseModel
from fastapi import Form, File, UploadFile


class UserCreateForm(BaseModel):
    username: str
    password: str

    @classmethod
    def as_form(cls,
                username: str = Form(...),
                password: str = Form(...)
                ):
        return cls(username=username,
                   password=password)


class UserLoginForm(UserCreateForm):
    pass


class MessageForm(BaseModel):
    message: str
    files: list[UploadFile]

    @classmethod
    def as_form(cls,
                message: str = Form(...),
                files: list[UploadFile] = File()):
        return cls(message=message,
                   files=files)
