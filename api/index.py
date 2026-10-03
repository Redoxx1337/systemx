import sys
from pathlib import Path

# Add the root of the SystemX project to PYTHONPATH so we can import backend modules
project_root = Path(__file__).resolve().parents[2]
sys.path.append(str(project_root))

# Import the FastAPI app defined in backend/main.py
from backend.main import app as fastapi_app

# Use Mangum (AWS Lambda adapter for ASGI)
from mangum import Mangum

handler = Mangum(fastapi_app)
