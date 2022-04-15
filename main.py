from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, status, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
import pyrebase, json

#Initialize Firebase
firebaseConfig={"apiKey": "AIzaSyDm4UDwR2iWO_zK2og_hd_Yt86W6sezYds",
  "authDomain": "fitdesign-18dfb.firebaseapp.com",
  "databaseURL": "https://fitdesign-18dfb-default-rtdb.firebaseio.com/",
  "projectId": "fitdesign-18dfb",
  "storageBucket": "fitdesign-18dfb.appspot.com",
  "messagingSenderId": "813772686232",
  "appId": "1:813772686232:android:aad8aa4b059d8e6d6b21ed"}

firebase=pyrebase.initialize_app(firebaseConfig)

db=firebase.database()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
app = FastAPI()


SECRET_KEY = "4b97e40df461128071d1abd62f3714eb09bac4e06c01b89e0aeef1ff46b17fc8" #openssl rand -hex 32
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 20

admin = {
    "asdf": {
        "username": "asdf",
        "hashed_password": "$2a$10$kkTZ4TL0tTlayVG6w5eSWOkPmDKf0AeiHhtgYZ0vF90DcBQP4uK/W", #asdf encrypt with bcrypt hash
        "disabled": False,
    }
}

class Item(BaseModel):
	id: int
	name: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(admin_db, username: str, password: str):
    user = get_user(admin_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(admin, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(admin, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get('/trash')
async def get_all_trash_info():
    plants = db.child("Trash").get()
    return Response(json.dumps(plants.val(), indent=2))

@app.get('/Users')
async def get_all_user(current_user: User = Depends(get_current_active_user)):
    users = db.child("Users").get()
    return Response(json.dumps(users.val(), indent=2))

@app.get('/trash/{id}')
async def get_plant_details(id: int):
    plants = db.child("Trash").get()
    return Response(json.dumps(plants.val()[id], indent=2))

@app.get('/sensor')
async def get_water_level(current_user: User = Depends(get_current_active_user)):
    water_level = db.child("Sensor").child("value").get()
    return Response(json.dumps(water_level.val(), indent=2))

@app.patch('/actuator/{status}')
async def on_off_water_pump(status: str, current_user: User = Depends(get_current_active_user)):
    if (status != "on") and (status != "off"):
        return "Input False"
    else:
        db.child("Sensor").child("message").set(status)
        return Response(json.dumps(db.child("Sensor").child("message").get().val(), indent=2))

@app.post('/user/{username}')
async def add_user(username: str, password: str, email:str, name:str, photo_url:str, current_user: User = Depends(get_current_active_user)):
    data = {"username" : username, "password" : password, "email_address": email, "nama": name, "url_photo_profile": photo_url}
    db.child("Users").child(username).set(data)
    user = db.child("Users").child(username).get().val()
    return Response(json.dumps(user, indent=2))