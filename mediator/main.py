from fastapi import FastAPI, Depends, HTTPException, Request, Form, Response, Cookie
from .auth import AuthHandler
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
app.add_middleware(
  CORSMiddleware,
  allow_origins=['*'],
  allow_credentials=True,
  allow_methods=["GET", "POST", "OPTIONS"], # include additional methods as per the application demand
  allow_headers=["Content-Type","Set-Cookie"], # include additional headers as per the application demand
)

auth_handler = AuthHandler()
admin_user = "admin"
admin_password = "$2b$12$gTl5nwodqeu1yn2T3LPKNOgJJqD6gKo7i0QRz1ATdD7HdTsvbJQeG"
# password = auth_handler.get_password_hash("upstream")
# print(password)

@app.get('/login')
def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post('/login')
def login(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    error = "Invalid Username / Password"
    print(username, password)

    if admin_user != username:
        raise HTTPException(status_code=401, detail='Invalid username and/or password')

    if (not auth_handler.verify_password(password, admin_password)):
        raise HTTPException(status_code=401, detail='Invalid username and/or password')

    token = auth_handler.encode_token(username)
    response.set_cookie(key="token", value=token, httponly=True)
    return { 'token': token }

@app.get('/read')
async def reading(token: Optional[str] = Cookie("token")):
    return token

# @app.post('/login')
# def login(auth_details: AuthDetails):
#     if user != auth_details.username:
#         raise HTTPException(status_code=401, detail='Invalid username and/or password')

#     if (not auth_handler.verify_password(auth_details.password, password)):
#         raise HTTPException(status_code=401, detail='Invalid username and/or password')

#     token = auth_handler.encode_token(user)
#     return { 'token': token }

@app.get('/unprotected')
def unprotected(request: Request):
    token = request.cookies.get("token")
    print(token)

    return { 'hello': 'world' }


@app.get('/protected')
def protected(username=Depends(auth_handler.auth_wrapper)):
    return { 'name': username }
