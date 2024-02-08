from typing import Any

from fastapi.responses import JSONResponse
from pydantic import BaseModel


def response(model: BaseModel,
             service_code: int = 200,
             exclude: set[int] | set[str] | dict[int, Any] | dict[str, Any] | None = None):
    return JSONResponse(model.model_dump(mode='json',
                                         exclude=exclude), service_code)
