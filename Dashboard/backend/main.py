from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client, Client
from pydantic import BaseModel
from jose import JWTError, jwt
from datetime import datetime, timedelta
import requests
import os
from dotenv import load_dotenv
from typing import List, Optional
import logging

load_dotenv()

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Supabase setup
supabase: Client = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))

# JWT setup
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Models
class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str
    role: str

class UserCreate(BaseModel):
    username: str
    password: str
    role: str

class Threat(BaseModel):
    id: int
    type: str
    value: str
    source: str
    timestamp: Optional[datetime]
    listing_reason: Optional[str]

class SourceCount(BaseModel):
    source: str
    count: int

# JWT functions
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return User(username=username, role=role)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Endpoints
@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user_data = supabase.table("users").select("*").eq("username", form_data.username).execute()
    if not user_data.data or user_data.data[0]["password"] != form_data.password:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    user = user_data.data[0]
    access_token = create_access_token(data={"sub": user["username"], "role": user["role"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/threats", response_model=List[Threat])
async def get_threats(current_user: User = Depends(get_current_user)):
    indicators = supabase.table("indicators").select("*").order("timestamp", desc=True, nulls_last=True).limit(50).execute()
    return indicators.data

@app.get("/threat_ips")
async def get_threat_ips(current_user: User = Depends(get_current_user)):
    ips = supabase.table("indicators").select("value").eq("type", "IP").execute()
    return ips.data

@app.get("/threat_domains")
async def get_threat_domains(current_user: User = Depends(get_current_user)):
    domains = supabase.table("indicators").select("value").eq("type", "Domain").execute()
    return domains.data

@app.get("/threat_urls")
async def get_threat_domains(current_user: User = Depends(get_current_user)):
    domains = supabase.table("indicators").select("value").eq("type", "URL").execute()
    return domains.data

@app.get("/threat_hashes")
async def get_threat_hashes(current_user: User = Depends(get_current_user)):
    try:
        hashes = supabase.table("indicators").select("value").eq("type", "Hash").execute()
        return hashes.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving hash threats: {str(e)}")

@app.get("/threat_ip_count")
async def get_threat_ip_count(current_user: User = Depends(get_current_user)):
    try:
        response = supabase.table("indicators").select("value", count="exact").eq("type", "IP").execute()
        ip_count = response.count
        return {"ip_count": ip_count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving IP count: {str(e)}")

@app.get("/threat_domain_count")
async def get_threat_domain_count(current_user: User = Depends(get_current_user)):
    try:
        response = supabase.table("indicators").select("value", count="exact").eq("type", "Domain").execute()
        domain_count = response.count
        return {"domain_count": domain_count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving domain count: {str(e)}")

@app.get("/threat_url_count")
async def get_threat_url_count(current_user: User = Depends(get_current_user)):
    try:
        response = supabase.table("indicators").select("value", count="exact").eq("type", "URL").execute()
        url_count = response.count
        return {"url_count": url_count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving URL count: {str(e)}")

@app.get("/threat_hash_count")
async def get_threat_hash_count(current_user: User = Depends(get_current_user)):
    try:
        response = supabase.table("indicators").select("value", count="exact").eq("type", "Hash").execute()
        hash_count = response.count
        return {"hash_count": hash_count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving hash count: {str(e)}")

@app.get("/source_count", response_model=List[SourceCount])
async def get_source_counts(current_user: User = Depends(get_current_user)):
    try:
        response = supabase.table("source_counts").select("*").execute()
        return response.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving source counts: {str(e)}")

@app.get("/geocode/{ip}")
async def geocode_ip(ip: str, current_user: User = Depends(get_current_user)):
    response = requests.get(f'http://ip-api.com/json/{ip}')
    data = response.json()
    return {"ip": ip, "lat": data.get("lat"), "lon": data.get("lon")}

@app.post("/refresh_feeds")
async def refresh_feeds(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    # Simulate feed refresh (replace with actual feed fetching logic)
    return {"status": "Feed refresh triggered"}

@app.post("/users")
async def create_user(user: UserCreate, current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    try:
        supabase.table("users").insert({
            "username": user.username,
            "password": user.password,  # Store plain text password (INSECURE)
            "role": user.role
        }).execute()
        return {"status": "User created"}
    except:
        raise HTTPException(status_code=400, detail="Username exists")

@app.get("/test-supabase")
async def test_supabase():
    try:
        data = supabase.table("users").select("*").execute()
        return {"status": "success", "data": data.data}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# SECURITY WARNING: Storing plain text passwords is insecure. Use hashed passwords (e.g., bcrypt) in production.