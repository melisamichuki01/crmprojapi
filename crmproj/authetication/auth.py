from datetime import timedelta,datetime
from typing import Annotated
from fastapi import APIRouter,Depends,HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status
from crmproj.model.models import Users
from crmproj.databases.database import SessionLocal
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm,OAuth2PasswordBearer
from jose import jwt,JWTError

auth_router = APIRouter(
    prefix= '/auth',
    tags=['auth']
    )


SECRET_KEY = '197b2c37c391bed93fe80344fe73b806947a65e36206e05a1a23c2fa12702fe3' 
ALGORITHM = 'HS256' # enforce security

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")

class CreateUSerRequest(BaseModel):
    username:str
    password:str
    
# define the Token class
class Token(BaseModel):
    # the access token string
    access_token: str
    # the token type string
    token_type: str
    
# create database session
def get_db():
    db = SessionLocal()
    try:
        yield db # pass db session to context
    finally:
        db.close() # close db session after usage
        
db_dependency = Annotated[Session,Depends(get_db)]
# Creating the User Model
@auth_router.post("/",status_code=status.HTTP_201_CREATED)
async def create_user(db:db_dependency,
                      create_user_request:CreateUSerRequest):
    # Creating a new user with hashed password
    create_user_model = Users(
        username=create_user_request.username,
        hashed_password = bcrypt_context.hash(create_user_request.password),
    )
    
    # Adding the user to the database
    db.add(create_user_model)
    
    # Committing the changes to the database
    db.commit()

@auth_router.post("/token",response_model=Token)
async def login_for_acess_token(form_data: Annotated[OAuth2PasswordRequestForm,Depends()],
                                                     db:db_dependency):
    user = authenticate_user(form_data.username, form_data.password,db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Incorrect username or password/ Couldn't Validate user")
    token =create_access_token(user.username,user.id,timedelta(minutes=20))
    
    return {'access_token':token,'token_type':'bearer'}

def authenticate_user(username:str,password:str,db):
    """Retrieve user, verify password, return user if authenticated."""
    
    # Query database for user with matching username
    user = db.query(Users).filter(Users.username == username).first()
    
    # Check if user exists
    if not user:
        return False
    
    # Verify hashed password matches provided password
    if not bcrypt_context.verify(password, user.hashed_password):
        return False
    
    # Return authenticated user
    return user

def create_access_token(username:str,user_id:int,expires_delta:timedelta):
    encode = {'sub':username,'id':user_id}
    expires = datetime.utcnow() + expires_delta
    encode.update({'exp':expires})
    return jwt.encode(encode,SECRET_KEY,algorithm=ALGORITHM)

async def get_current_user(token: Annotated[str,Depends(oauth2_bearer)]): 
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='Could not validate user.')
        return {'username': username, 'id': user_id}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not validate user.')



