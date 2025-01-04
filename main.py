from fastapi import FastAPI, Depends
import models
from database import engine
from routers import similarity


app = FastAPI()

models.Base.metadata.create_all(bind=engine)


app.include_router(similarity.router)
