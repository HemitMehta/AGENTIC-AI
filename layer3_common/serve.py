import os

import uvicorn

from .security import directory, secret

if __name__ == "__main__":
    secret("client.key")
    uvicorn.run(os.environ["SERVICE_MODULE"], host="0.0.0.0", port=int(os.environ["SERVICE_PORT"]),
                ssl_certfile=str(directory() / "tls.crt"), ssl_keyfile=str(directory() / "tls.key"),
                proxy_headers=False)
