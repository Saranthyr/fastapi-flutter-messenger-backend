from pydantic import BaseModel
from fastapi import Form


class UserCreate(BaseModel):
    username: str