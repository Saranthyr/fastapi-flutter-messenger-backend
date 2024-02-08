import datetime
from typing import List

from pydantic import BaseModel


class FileResponse(BaseModel):
    id: str
    filename: str
    mime: str
    contents: str
    created_at: datetime.datetime


class MessageResponse(BaseModel):
    send_by: str
    contents: str
    attachments: List[str]
    send_at: datetime.datetime


class ServiceMessageResponse(BaseModel):
    message: str


class AccessTokenResponse(BaseModel):
    access_token: str


class UserDataResponse(BaseModel):
    user_id: str
    username: str
    online: bool
    last_online: datetime.datetime
