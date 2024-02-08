import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

engine = create_engine(f'postgresql+psycopg://{os.environ["DB_USER"]}:{os.environ["DB_PASSWORD"]}@'
                       f'{os.environ["DB_HOST"]}:{os.environ["DB_PORT"]}/{os.environ["DB_NAME"]}',
                       pool_size=20,
                       max_overflow=0,
                       pool_pre_ping=True,
                       echo=True)
Session = sessionmaker(engine, autoflush=False)
