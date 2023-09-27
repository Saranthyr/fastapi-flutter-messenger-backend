import datetime
from typing import List, Annotated

from pydantic import BaseModel, Strict


class FileResponse(BaseModel):
    id: str
    filename: str
    mime: str
    contents: str

class MessageResponse(BaseModel):
    send_by: str
    contents: str
    attachments: List[FileResponse]


class ServiceMessageResponse(BaseModel):
    message: str


class AccessTokenResponse(BaseModel):
    access_token: str


class UserDataResponse(BaseModel):
    user_id: str
    username: str
    online: bool
    last_online: datetime.datetime
