# api/index.py
# Vercel entry point for FastAPI application

# Import the FastAPI app defined in backend/main.py
from backend.main import app

# Export the ASGI app for Vercel. Vercel looks for a top‑level variable named
# `app`, `application`, or `handler`. By exposing `app` directly the deployment
# will succeed.
