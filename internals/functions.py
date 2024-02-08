from typing import Any

from fastapi.responses import JSONResponse
from pydantic import BaseModel


def response(model: BaseModel | None,
             service_code: int = 200,
             exclude: set[int] | set[str] | dict[int, Any] | dict[str, Any] | None = None):
    if isinstance(model, BaseModel):
        return JSONResponse(model.model_dump(mode='json',
                                             exclude=exclude), service_code)
    else:
        return JSONResponse(model, service_code)
