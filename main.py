from fastapi import FastAPI, Form, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from passlib.hash import bcrypt
from database import Base, engine, get_db, User


app = FastAPI()

templates = Jinja2Templates(directory="template")

Base.metadata.create_all(bind=engine)


@app.get("/")
async def home(request: Request):
    """
    Render the home page for logged-in users.
    """
    username = request.cookies.get("username")
    if not username:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("home.html", {"request": request, "username": username})

@app.get("/signup")
async def signup_form(request: Request):
    """
    Render the signup form.
    """
    return templates.TemplateResponse("Signup.html", {"request": request})


@app.post("/signup")
async def signup_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """
    Handle user signup.
    """
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        return templates.TemplateResponse(
            "signup.html",
            {"request": request, "error": "Username already exists."},
        )

    hashed_password = bcrypt.hash(password)
    new_user = User(username=username, password=hashed_password)
    db.add(new_user)
    db.commit()
    return templates.TemplateResponse(
        "Signup.html",
        {"request": request, "success": "User registered successfully! You can now log in."},
    )


@app.get("/login")
async def login_form(request: Request):
    """
    Render the login form.
    """
    return templates.TemplateResponse("Login.html", {"request": request})


@app.post("/login")
async def login_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """
    Handle user login.
    """
    user = db.query(User).filter(User.username == username).first()
    if not user or not bcrypt.verify(password, user.password):
        return templates.TemplateResponse(
            "Login.html",
            {"request": request, "error": "Invalid username or password."},
        )

    # Set a cookie (for simplicity; use a better session system in production)
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(key="username", value=username)
    return response


@app.get("/logout")
async def logout_user():
    """
    Handle user logout by clearing the session.
    """
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("username")
    return response
