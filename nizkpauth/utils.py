import base64


def from_string_to_binary(string):
    return bytes(string, "utf-8")


def encode_string(string) -> str:
    string_bytes = from_string_to_binary(string)
    encoded = base64.b64encode(string_bytes).decode()
    return encoded


def decode_string(string) -> str:
    decoded = base64.b64decode(string).decode()
    return decoded
