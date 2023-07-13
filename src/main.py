import jwt
import json
import sys
from jwcrypto import jwk
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

ALGORITHM = 'RS256'

private_key = rsa.generate_private_key(
  public_exponent=65537,
  key_size=2048,
  backend=default_backend()
)

# Convert to PEM format
private_pem = private_key.private_bytes(
  encoding=serialization.Encoding.PEM,
  format=serialization.PrivateFormat.PKCS8,
  encryption_algorithm=serialization.NoEncryption()
)

# Save the private key in a file
with open('id_rsa', 'wb') as f:
  f.write(private_pem)

# Get the public key
public_key = private_key.public_key()

# Convert to PEM format
public_pem = public_key.public_bytes(
  encoding=serialization.Encoding.PEM,
  format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Save the public key in a file
with open('id_rsa.pub', 'wb') as f:
  f.write(public_pem)

with open('id_rsa_jwk.pub', 'wb') as f:
  f.write(bytes(jwk.JWK.from_pem(public_pem).export_public(), sys.getdefaultencoding()))


# Create a JWT token signed with the private key
with open('assets/payload.json', 'r') as f:
  json_payload = json.loads(f.read())
  jwt_token = jwt.encode(json_payload, private_key, algorithm=ALGORITHM)

  with open('jwt', 'wb') as jwt_file:
    jwt_file.write(bytes(jwt_token, sys.getdefaultencoding()))

