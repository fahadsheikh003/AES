# function to pad bytes in a block in PKCS#7 format
def pad(data_to_pad: bytes, block_size: int = 16) -> bytes:
    padding_len = block_size - len(data_to_pad) % block_size
    padding = bytes([padding_len] * padding_len)
    return data_to_pad + padding

# function to unpad a block
def unpad(padded_data: bytes, block_size: int = 16) -> bytes:
    padded_data_len = len(padded_data)

    if padded_data_len == 0 or padded_data_len % block_size:
        raise ValueError("Invalid Data")

    padded_len = padded_data[-1]
    if padded_len < 1 or padded_len > min(block_size, padded_data_len):
        raise ValueError("Padding is incorrect.")

    if padded_data[-padded_len : ] != bytes([padded_len] * padded_len):
        raise ValueError("PKCS#7 padding is incorrect.")

    return padded_data[ : -padded_len]