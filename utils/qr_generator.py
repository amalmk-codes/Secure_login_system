import base64
import io

import qrcode


def generate_qr_data_uri(data):
    buffer = io.BytesIO()
    image = qrcode.make(data)
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"
