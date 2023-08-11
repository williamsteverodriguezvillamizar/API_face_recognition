from fastapi import FastAPI, UploadFile, Form, HTTPException, File, Depends
from fastapi.security.oauth2 import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional, Union
from io import BytesIO
import uvicorn
import multiprocessing
import jwt


app = FastAPI(
    title="Sistema de Comparación Biométrica",
    description="API para comparación biométrica de huellas dactilares y rostros",
    version="1.0.0",
    contact={
        "name": "William Rodriguez",
        "email": "wisrovi.rodriguez@gmail.com",
        "url": "https://www.linkedin.com/in/wisrovi-rodriguez/",
    },
    license_info={
        "name": "Licencia BSD",
        "url": "https://opensource.org/licenses/BSD-3-Clause",
    },
    terms_of_service="https://example.com/terms",
    openapi_tags=[
        {"name": "Fingerprint", "description": "Operaciones con huellas dactilares"},
        {"name": "Face", "description": "Operaciones con rostros"},
    ],
    redoc_url="/redoc",
    docs_url="/docs",
    redoc_oauth2_redirect_url="/redoc/oauth2-redirect",
)

# Cambiar el título en la documentación de Swagger UI
app.openapi_schema["info"]["title"] = "API de Comparación Biométrica"

# Agregar el logotipo personalizado en la documentación de Swagger UI
app.openapi_schema["info"]["x-logo"] = {
    "url": "https://us.123rf.com/450wm/engabito/engabito1906/engabito190600405/125379784-human-face-recognition-scanning-system-vector-illustration.jpg"
}

# Términos de Servicio
terms_of_service = """
Sin previo aviso, podemos lanzar actualizaciones y mejoras en el servicio en cualquier momento. Apreciamos sus sugerencias y comentarios para mejorar aún más la experiencia de usuario. Si bien el uso de este código es gratuito, solicitamos que se haga mención del autor, William Rodriguez, en el proyecto donde se utilice este código. Al utilizar esta API, acepta cumplir con estos términos de servicio.

Tenga en cuenta que estos términos de servicio pueden estar sujetos a cambios en el futuro. Le recomendamos que revise periódicamente esta página para estar al tanto de las actualizaciones.
"""

app.openapi_schema["info"]["termsOfService"] = terms_of_service









# ----------------------------------------------




# Secret key for JWT encoding/decoding (replace with your secret key)
SECRET_KEY = "your-secret-key"

# OAuth2PasswordBearer provides the OAuth2 security scheme for JWT authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class Token(BaseModel):
    access_token: str
    token_type: str


class User(BaseModel):
    username: str


class UserInDB(User):
    hashed_password: str


# Simulated user database (replace with a real database)
fake_users_db = {
    "username": {
        "username": "username",
        # password: 12345678
        "hashed_password": "$2b$12$A8RR/50.LF08RQK5bo3njOvy8rQQEVkiBX03J/3vFXiR0VdGcAnZG"
    }
}


def verify_password(plain_password, hashed_password):
    return plain_password == hashed_password


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict):
    to_encode = data.copy()
    access_token = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
    return access_token


# Token endpoint to generate JWT tokens
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


def is_authenticated(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        token_data = Token(access_token=token, token_type="bearer")
        return token_data
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

























# Allowed file extensions and corresponding MIME types
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png"}
ALLOWED_MIME_TYPES = {"image/jpeg", "image/png"}

def is_allowed_file(filename):
    """
    Check if the provided filename has an allowed extension.
    """
    return any(filename.endswith(ext) for ext in ALLOWED_EXTENSIONS)

def is_allowed_mime_type(content_type):
    """
    Check if the provided MIME type is allowed.
    """
    return content_type in ALLOWED_MIME_TYPES




def compare_face_vs_face(image: UploadFile, face_file: UploadFile) -> Dict[str, Any]:
    """
    Compare an image against a single face.

    Args:
        image (UploadFile): The image to compare.
        face_file (UploadFile): The face image for comparison.

    Returns:
        dict: A dictionary containing the comparison result.
    """
    # Perform your actual face comparison logic here between the image and the face

    # Example result for demonstration purposes
    similarity_score = 0.85  # Replace with your actual similarity score
    match = similarity_score >= 0.8  # Replace with your actual matching criteria

    # Prepare the comparison result dictionary
    comparison_result = {"face_file": face_file.filename,
                         "similarity_score": similarity_score,
                         "match": match}

    return comparison_result



class FingerprintCompareResult(BaseModel):
    fingerprint: str
    match: bool

class FaceCompareResult(BaseModel):
    image_filename: str
    match: bool

class FaceFingerprintCompareResult(BaseModel):
    image_filename: str
    fingerprint: Union[str, List[str]]
    match_result: bool
    matched_indices: Optional[List[int]]

class FingerprintFingerprintCompareResult(BaseModel):
    fingerprint1: Union[str, List[str]]
    fingerprint2: Union[str, List[str]]
    match_result: bool
    matched_indices: Optional[List[int]]
    
class FaceCompareFaceResult(BaseModel):
    image_filename: str
    results: List[FaceCompareResult]

class ImageCompareResult(BaseModel):
    image_filename: str
    match: bool


# 1. compare fingerprint vs fingerprint
@app.post("/fingerprint_vs_database", response_model=List[FingerprintCompareResult])
async def fingerprint_vs_database(
    fingerprints: Union[str, List[str]] = Form(...),
    company: Optional[str] = Form(None),
    group: Optional[str] = Form(None),
    token_data: Token = Depends(is_authenticated)
) -> List[FingerprintCompareResult]:
    """
    Compare fingerprint(s) against the database with optional filters.

    Args:
        fingerprints (Union[str, List[str]]): Fingerprint(s) to compare.
        company (Optional[str]): Company name for filtering (optional).
        group (Optional[str]): Group name for filtering (optional).
        token_data (Token): Token data for authentication.

    Returns:
        List[FingerprintCompareResult]: A list of comparison results for each fingerprint.
    """
    if isinstance(fingerprints, str):
        fingerprints = [fingerprints]

    comparison_results = []

    def compare_fingerprint_to_database(
        fingerprint: str, company: Optional[str], group: Optional[str]
    ) -> FingerprintCompareResult:
        return FingerprintCompareResult(fingerprint=fingerprint, match=True)  # Replace with your actual comparison logic

    for fingerprint in fingerprints:
        comparison_result = compare_fingerprint_to_database(fingerprint, company, group)
        comparison_results.append(comparison_result)

    return comparison_results

# 2. compare face vs faces
@app.post("/faces_vs_database", response_model=List[FaceCompareResult])
async def faces_vs_database(
    images: Union[UploadFile, List[UploadFile]] = File(...),
    company: Optional[str] = Form(None),
    group: Optional[str] = Form(None),
    token_data: Token = Depends(is_authenticated)
) -> List[FaceCompareResult]:
    """
    Compare face image(s) against the database with optional filters.

    Args:
        images (Union[UploadFile, List[UploadFile]]): Face image(s) to compare.
        company (Optional[str]): Company name for filtering (optional).
        group (Optional[str]): Group name for filtering (optional).
        token_data (Token): Token data for authentication.

    Returns:
        List[FaceCompareResult]: A list of comparison results for each image.
    """
    if isinstance(images, UploadFile):
        images = [images]

    comparison_results = []

    def compare_face_to_database(
        image: UploadFile, company: Optional[str], group: Optional[str]
    ) -> FaceCompareResult:
        return FaceCompareResult(image_filename=image.filename, match=True)  # Replace with your actual comparison logic

    for image in images:
        comparison_result = compare_face_to_database(image, company, group)
        comparison_results.append(comparison_result)

    return comparison_results

# 3. compare face vs fingerprint
@app.post("/face_vs_fingerprint", response_model=FaceFingerprintCompareResult)
async def face_vs_fingerprint(
    image: UploadFile = File(...),
    fingerprint_or_list: Union[str, List[str]] = Form(...),
    token_data: Token = Depends(is_authenticated)
) -> FaceFingerprintCompareResult:
    """
    Compare a face image against a fingerprint or a list of fingerprints.

    Args:
        image (Union[UploadFile, List[UploadFile]]): The face image to compare.
        fingerprint_or_list (Union[str, List[str]]): The fingerprint or list of fingerprints to compare against.
        token_data (Token): Token data for authentication.

    Returns:
        FaceFingerprintCompareResult: A dictionary containing the comparison result.
    """
    if not is_allowed_file(image.filename) or not is_allowed_mime_type(image.content_type):
        raise HTTPException(status_code=400, detail="Invalid file format")
    
    # Save face image to BytesIO buffer
    image_buffer = BytesIO()
    image_buffer.write(image.file.read())
    image_buffer.seek(0)
    
    if isinstance(fingerprint_or_list, str):
        # Compare face image against a single fingerprint
        match_result = True
        return FaceFingerprintCompareResult(
            image_filename=image.filename,
            fingerprint=fingerprint_or_list,
            match_result=match_result
        )
    elif isinstance(fingerprint_or_list, list):
        # Compare face image against a list of fingerprints
        matched_indices = [1, 3]
        return FaceFingerprintCompareResult(
            image_filename=image.filename,
            fingerprint=fingerprint_or_list,
            match_result=False,
            matched_indices=matched_indices
        )
    else:
        raise HTTPException(status_code=400, detail="Invalid input for fingerprint_or_list")

# 4. compare fingerprint vs face
@app.post("/fingerprint_vs_fingerprint", response_model=FingerprintFingerprintCompareResult)
async def fingerprint_vs_fingerprint(
    fingerprint1: Union[str, List[str]] = Form(...),
    fingerprint2_or_list: Union[str, List[str]] = Form(...),
    token_data: Token = Depends(is_authenticated)
) -> FingerprintFingerprintCompareResult:
    """
    Compare a fingerprint against another fingerprint or a list of fingerprints.

    Args:
        fingerprint1 (Union[str, List[str]]): The first fingerprint to compare.
        fingerprint2_or_list (Union[str, List[str]]): The second fingerprint or list of fingerprints to compare against.
        token_data (Token): Token data for authentication.

    Returns:
        FingerprintFingerprintCompareResult: A dictionary containing the comparison result.
    """
    if isinstance(fingerprint1, str) and isinstance(fingerprint2_or_list, str):
        # Compare two fingerprints
        match_result = True
        return FingerprintFingerprintCompareResult(
            fingerprint1=fingerprint1,
            fingerprint2=fingerprint2_or_list,
            match_result=match_result
        )
    elif isinstance(fingerprint1, str) and isinstance(fingerprint2_or_list, list):
        # Compare a fingerprint against a list of fingerprints
        matched_indices = [1, 3]
        return FingerprintFingerprintCompareResult(
            fingerprint1=fingerprint1,
            fingerprint2=fingerprint2_or_list,
            match_result=False,
            matched_indices=matched_indices
        )
    elif isinstance(fingerprint1, list) and isinstance(fingerprint2_or_list, str):
        # Compare a list of fingerprints against a fingerprint
        matched_indices = [1, 3]
        return FingerprintFingerprintCompareResult(
            fingerprint1=fingerprint1,
            fingerprint2=fingerprint2_or_list,
            match_result=False,
            matched_indices=matched_indices
        )
    elif isinstance(fingerprint1, list) and isinstance(fingerprint2_or_list, list):
        # Compare a list of fingerprints against another list of fingerprints
        matched_indices = [1, 3]
        return FingerprintFingerprintCompareResult(
            fingerprint1=fingerprint1,
            fingerprint2=fingerprint2_or_list,
            match_result=False,
            matched_indices=matched_indices
        )
    else:
        raise HTTPException(status_code=400, detail="Invalid input for fingerprint2_or_list")

# 5. compare face vs face   
@app.post("/face_vs_face", response_model=FaceCompareFaceResult)
async def face_vs_faces(
    image: Union[UploadFile, List[UploadFile]] = File(...),
    list_faces: Union[UploadFile, List[UploadFile]] = File(...),
    token_data: Token = Depends(is_authenticated)
) -> FaceCompareFaceResult:
    """
    Compare an image against a single face or a list of faces.

    Args:
        image (UploadFile): The image to compare.
        list_faces (Union[UploadFile, List[UploadFile]]): A single face image or a list of face images.
        token_data (Token): Token data for authentication.

    Returns:
        FaceCompareFaceResult: A dictionary containing the comparison result.
    """
    image_buffers = []
    if isinstance(image, UploadFile):
        # Save image to BytesIO buffer
        image_buffer = BytesIO()
        image_buffer.write(image.file.read())
        image_buffer.seek(0)
        image_buffers.append(image_buffer)
    elif isinstance(image, List):
        # Save images to BytesIO buffers        
        for img in image:
            image_buffer = BytesIO()
            image_buffer.write(img.file.read())
            image_buffer.seek(0)
            image_buffers.append(image_buffer)
    
    for image_buffer in image_buffers:
        if not is_allowed_file(image.filename) or not is_allowed_mime_type(image.content_type):
            raise HTTPException(status_code=400, detail="Invalid file format")
        
    list_faces_buffers = []
    if isinstance(list_faces, UploadFile):
        # Save image to BytesIO buffer
        list_faces_buffer = BytesIO()
        list_faces_buffer.write(list_faces.file.read())
        list_faces_buffer.seek(0)
        list_faces_buffers.append(list_faces_buffer)

    elif isinstance(list_faces, List):
        # Save images to BytesIO buffers        
        for img in list_faces:
            list_faces_buffer = BytesIO()
            list_faces_buffer.write(img.file.read())
            list_faces_buffer.seek(0)
            list_faces_buffers.append(list_faces_buffer)

    for list_faces_buffer in list_faces_buffers:
        if not is_allowed_file(list_faces.filename) or not is_allowed_mime_type(list_faces.content_type):
            raise HTTPException(status_code=400, detail="Invalid file format")
        
    comparison_results = []
    for image_buffer in image_buffers:
        for list_faces_buffer in list_faces_buffers:
            comparison_result = compare_face_vs_face(image_buffer, list_faces_buffer)
            comparison_results.append(comparison_result)

    return FaceCompareFaceResult(
        image_filename=image.filename,
        results=comparison_results
    )









@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Sistema de Comparación Biométrica</title>
        <meta name="description" content="API para comparación biométrica de huellas dactilares y rostros">
        <meta name="author" content="William Rodriguez">
        <link rel="icon" type="image/png" href="https://us.123rf.com/450wm/engabito/engabito1906/engabito190600405/125379784-human-face-recognition-scanning-system-vector-illustration.jpg">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
        <style>
            body {
                padding: 20px;
            }
            header {
                background-color: #343a40;
                padding: 10px;
                color: white;
                text-align: center;
            }
            footer {
                background-color: #343a40;
                padding: 10px;
                color: white;
                text-align: center;
            }
            .btn {
                margin: 5px;
            }
        </style>
    </head>
    <body>

    <header>
        <h1>Sistema de Comparación Biométrica</h1>
        <a href="https://www.linkedin.com/in/wisrovi-rodriguez/" target="_blank" class="btn btn-primary">
            Contacto en LinkedIn
        </a>
        <a href="/docs" target="_blank" class="btn btn-secondary">
            Documentación - Swagger UI
        </a>
        <a href="/redoc" target="_blank" class="btn btn-secondary">
            Documentación - ReDoc
        </a>
    </header>

    <h2>Prueba de Servicios POST</h2>

    <h3>Comparar Huellas Dactilares con Base de Datos</h3>
    <form action="/fingerprint_vs_database" method="post">
        Fingerprint: <input type="text" name="fingerprints" class="form-control"><br>
        Company: <input type="text" name="company" class="form-control"><br>
        Group: <input type="text" name="group" class="form-control"><br>
        <button type="submit" class="btn btn-primary">Enviar</button>
    </form>

    <h3>Comparar Rostros con Base de Datos</h3>
    <form action="/faces_vs_database" method="post" enctype="multipart/form-data">
        Image: <input type="file" name="images" multiple class="form-control-file"><br>
        Company: <input type="text" name="company" class="form-control"><br>
        Group: <input type="text" name="group" class="form-control"><br>
        <button type="submit" class="btn btn-primary">Enviar</button>
    </form>

    <h3>Comparar Rostro con Huella Dactilar</h3>
    <form action="/face_vs_fingerprint" method="post">
        Image: <input type="file" name="image" class="form-control-file"><br>
        Fingerprint: <input type="text" name="fingerprint_or_list" class="form-control"><br>
        <button type="submit" class="btn btn-primary">Enviar</button>
    </form>

    <h3>Comparar Huella Dactilar con Huella Dactilar</h3>
    <form action="/fingerprint_vs_fingerprint" method="post">
        Fingerprint 1: <input type="text" name="fingerprint1" class="form-control"><br>
        Fingerprint 2: <input type="text" name="fingerprint2_or_list" class="form-control"><br>
        <button type="submit" class="btn btn-primary">Enviar</button>
    </form>

    <h3>Comparar Rostro con Rostros</h3>
        <form action="/face_vs_face" method="post" enctype="multipart/form-data">
        Image: <input type="file" name="image" class="form-control-file"><br>
        Face Images: <input type="file" name="list_faces" multiple class="form-control-file"><br>
        <button type="submit" class="btn btn-primary">Enviar</button>
    </form>

    <footer>
        <p>&copy; 2023 William Rodriguez. Todos los derechos reservados. | <a href="/license">Licencia BSD</a></p>
    </footer>

    </body>
    </html>
    """











# The main block to run the FastAPI application
if __name__ == "__main__":
    uvicorn_options = {
        "host": "0.0.0.0",
        "port": 8000,
        "reload": True,
        "workers": multiprocessing.cpu_count() * 2 + 1,  # Make sure there are enough workers
    }

    uvicorn.run(app, **uvicorn_options)
