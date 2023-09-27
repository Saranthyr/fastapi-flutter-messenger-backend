import datetime

from pydantic import BaseModel


class MessageResponse(BaseModel):
    message: str


class AccessTokenResponse(BaseModel):
    access_token: str


class UserDataResponse(BaseModel):
    user_id: str
    username: str
    online: bool
    last_online: datetime.datetime
