from constants import SBOX, INVERSE_SBOX, FIXED_MATRIX, INVERSE_FIXED_MATRIX

# function to substitute a byte with byte for a 4x4 matrix
def byte_substitution_matrix(input: list) -> list:
    output = []

    if len(input) != 4 or len(input[0]) != 4:
        return output

    for row in input:
        output.append(byte_substitution_vector(row))

    return output

# function to substitute a byte with byte for a vector of length 4
def byte_substitution_vector(input: list) -> list:
    output = []

    if len(input) != 4:
        return output

    for val in input:
        r = (val & 0b11110000) >> 4
        c = val & 0b1111

        output.append(SBOX[r][c])

    return output

# function to (inverse) substitute a byte with byte for a 4x4 matrix
def inverse_byte_substitution_matrix(input: list) -> list:
    output = []

    if len(input) != 4 or len(input[0]) != 4:
        return output

    for index, row in enumerate(input):
        output.append([])
        for val in row:
            r = (val & 0b11110000) >> 4
            c = val & 0b1111

            output[index].append(INVERSE_SBOX[r][c])

    return output

# function to take xor of two lists
def xor_of_vector(L1: list, L2: list) -> list:
    if len(L1) != len(L2):
        return []
    return [value ^ L2[index] for index, value in enumerate(L1)]

# function to take xor of two matrices
def xor_of_matrix(L1: list, L2: list) -> list:
    if len(L1) != len(L2):
        return []
    return [xor_of_vector(value, L2[index]) for index, value in enumerate(L1)]

# function to convert a string into a matrix (row-major) of Yx4 where Y is number of rows
def string_to_matrix_row_wise(string: str, ini_quads: int = 4) -> list:
    return [[ord(ch) for ch in string[i * 4: (i * 4) + 4]] for i in range(ini_quads)]

# function to convert string to bytes (0-255)
def string_to_bytes(string: str) -> bytes:
    output = bytes()
    for char in string:
        output += ord(char).to_bytes(1, 'little')
    return output

# function to convert bytes into string (not like str.decode)
def bytes_to_string(input: bytes) -> str:
    return "".join(chr(char) for char in input)

# function to convert bytes into a matrix (row-major) of Yx4 where Y is number of rows
def bytes_to_matrix_row_wise(input: bytes, ini_quads: int = 4) -> list:
    return [[ch for ch in input[i * 4: (i * 4) + 4]] for i in range(ini_quads)]

# function to construct a state matrix (column major) from a list, string, or bytes
def construct_state_matrix(input: str | bytes | list) -> list:
    if isinstance(input, bytes):
        input = bytes_to_matrix_row_wise(input)
    elif isinstance(input, str):
        input = string_to_matrix_row_wise(input)
    return [[input[j][i] for j in range(len(input))] for i in range(len(input[0]))]

# function to convert state matrix (column-major) to bytes
def state_matrix_to_bytes(input: list) -> bytes:
    input = construct_state_matrix(input)
    output = bytes()
    for row in input:
        for val in row:
            output += val.to_bytes(1, 'little')
    return output

# function for left rotation of a vector
def cyclic_left_shift_vector(List: list, count: int = 1) -> list:
    return List[count:] + List[:count]

# function for right rotation of a vector
def cyclic_right_shift_vector(List: list, count: int = 1) -> list:
    return List[len(List) - count : ] + List[ : len(List) - count ]

# function to get a number in power 2
def get_int_in_power_of_2(input: int) -> list:
    output = []
    input = bin(input)[2:][::-1]
    for index, value in enumerate(input):
        if value == '1':
            output.append(index)
    return output

# function to handle overflow in galois field
def handle_overflow(value: int) -> int:
    if value <= 255:
        return value
    else:
        return (value & 255) ^ 0x1b

# function to handle multiplication using shifting
def handle_multiplication(multiplicand: int, multiplier: int) -> int:
    operations = []
    orig_multiplicand = multiplicand
    
    r = multiplier % 2
    q = multiplier // 2
    
    while q != 0:
        operations.append(q and r)

        r = q % 2
        q = q // 2

    operations = operations[::-1]
    for operation in operations:
        multiplicand = handle_overflow(multiplicand << 1)
        if operation:
            multiplicand ^= orig_multiplicand

    return multiplicand

# function to multiply FIXED MATRIX of Rijndael with state matrix
def mix_columns(input: list) -> list:
    output = [[0 for _ in L] for L in input]

    for i in range(len(FIXED_MATRIX)):
        for j in range(len(input[0])):
            for k in range(len(input)):
                output[i][j] ^= handle_multiplication(input[k][j], FIXED_MATRIX[i][k])
                
    return output
     
# function for inverse multiplication of FIXED MATRIX of Rijndael with state matrix
def inverse_mix_columns(input: list) -> list:
    output = [[0 for _ in L] for L in input]

    for i in range(len(INVERSE_FIXED_MATRIX)):
        for j in range(len(input[0])):
            for k in range(len(input)):
                output[i][j] ^= handle_multiplication(input[k][j], INVERSE_FIXED_MATRIX[i][k])
                
    return output
