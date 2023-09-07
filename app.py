from typing import Union

from fastapi import FastAPI


app = FastAPI()


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
