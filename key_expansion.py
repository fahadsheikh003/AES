from utils import byte_substitution_vector, bytes_to_matrix_row_wise, xor_of_vector, cyclic_left_shift_vector, string_to_matrix_row_wise

class Key_Expansion:
    def __init__(self, key: str | bytes, ini_quads: int, bytes_quads: int) -> None:
        # expanding keys based on type of key where ini_quads are initial quadrants of key i.e., 4 in case 128 bit AES
        if isinstance(key, bytes):
            self.keys = bytes_to_matrix_row_wise(key, ini_quads)
            self.__find_keys(ini_quads, bytes_quads)
        
        if isinstance(key, str):
            self.keys = string_to_matrix_row_wise(key, ini_quads)
            self.__find_keys(ini_quads, bytes_quads)
        else:
            self.keys = []

    # recursive function to find round constant
    def __find_round_constant(self, round: int, value: int = 1) -> int:
        if round == 1:
            return value
        return self.__find_round_constant(round - 1, ((value << 1) & 0b11111111) ^ 0x1B if value << 1 > 255 else value << 1)

    # function for key expansion
    def __find_keys(self, ini_quads, total_quads) -> None:
        for i in range(ini_quads, total_quads):
            temp = [*self.keys[i - 1]]
            if i % ini_quads == 0:
                temp = cyclic_left_shift_vector(temp)
                temp = byte_substitution_vector(temp)
                round_constant = [0] * 4
                round_constant[0] = self.__find_round_constant(i // ini_quads)
                temp = xor_of_vector(temp, round_constant)
            elif ini_quads == 8 and i % 4 == 0:
                temp = byte_substitution_vector(temp)

            self.keys.append(xor_of_vector(self.keys[i - ini_quads], temp))