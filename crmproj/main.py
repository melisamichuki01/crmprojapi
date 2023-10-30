from fastapi import FastAPI,status,Depends,HTTPException
from crmproj.model import models
from crmproj.databases.database import engine,SessionLocal
from crmproj.authetication import auth
from crmproj.authetication.auth import get_current_user
from typing import Annotated
from sqlalchemy.orm import Session

app = FastAPI()
app.include_router(auth.auth_router)
#app.include_router(auth.get_current_user)

models.Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db # pass db session to context
    finally:
        db.close() # close db session after usage
        
db_dependency = Annotated[Session,Depends(get_db)]
user_dependency = Annotated[dict,Depends(get_current_user)]

@app.post("/", status_code=status.HTTP_200_OK)
async def user(user: user_dependency,db:db_dependency):
    if user is None:
        raise HTTPException(status_code=401,detail='Auth Failed')
    return{"User":user}