"""An implementation of the ElsieFour(LC4) Encryption Algorithm
without the use of numpy for list manipuation"""

ALPHABET = "#_23456789abcdefghijklmnopqrstuvwxyz"
VECTORS = {i:[n%6, n//6] for n, i in enumerate(ALPHABET)}

def shift_row(s_box, row):
    """Shift the given row of the s_box by 1 to the right"""
    s_box[row] = s_box[row][5] + s_box[row][:5]
    return s_box

def shift_column(s_box, col):
    """Shift the given column of the s_box by 1 down"""
    cpy_box = [[], [], [], [], [], []]
    for i, row in enumerate(s_box):
        cpy_box[i] = row
    cpy_box[0] = s_box[0][:col] + s_box[5][col] + s_box[0][col+1:]
    cpy_box[1] = s_box[1][:col] + s_box[0][col] + s_box[1][col+1:]
    cpy_box[2] = s_box[2][:col] + s_box[1][col] + s_box[2][col+1:]
    cpy_box[3] = s_box[3][:col] + s_box[2][col] + s_box[3][col+1:]
    cpy_box[4] = s_box[4][:col] + s_box[3][col] + s_box[4][col+1:]
    cpy_box[5] = s_box[5][:col] + s_box[4][col] + s_box[5][col+1:]
    return cpy_box

def shift_s_box(s_box, marker, p_xy, cipherletter):
    """Conduct the s_box shifting and marker reassignment operations"""
    # Shift Plaintext Row Horizonatally Right by 1
    s_box = shift_row(s_box, p_xy[1])

    # Get cipherletters position incase it has been shifted
    c_col = [row.index(cipherletter) for row in s_box if cipherletter in row][0]

    # Shift Ciphertext Column Vertically Down by 1
    s_box = shift_column(s_box, c_col)

    # Get marker xy and cipher shift values then shift marker
    m_xy = [(row.index(marker), i) for i, row in enumerate(s_box) if marker in row][0]
    c_shifts = (VECTORS[cipherletter][0], VECTORS[cipherletter][1])
    marker = s_box[(m_xy[1] + c_shifts[1]) % 6][(m_xy[0] + c_shifts[0]) % 6]

    return s_box, marker

def elsie_four(key, message):
    """Validates the input message and key and then iterates over each letter
    in the decrypting it unless the message was preceded by the '%' token to
    run encryption of the message instead"""

    encrypting = False
    if message.startswith('%'):
        encrypting = True
        message = message[1:]

    if len(key) != 36:
        return '--Error: Please provide a key of length 36--'
    if len(set(ALPHABET + key + message)) > 36:
        return '--Error: invalid characters in key/message--'

    # Create a 6 x 6 s_box from the user input key
    s_box = [key[:6], key[6:12], key[12:18], key[18:24], key[24:30], key[30:]]

    # Set the marker to the top left value
    marker = s_box[0][0]
    result = ""

    for letter in message:
        # Compute the marker's xy shift values
        m_shifts = (VECTORS[marker][0], VECTORS[marker][1])

        # Get the xy of the plaintext letter in the s_box
        input_xy = [(row.index(letter), i) for i, row in enumerate(s_box) if letter in row][0]

        if encrypting:
            # Compute xy of the ciphertext by adding marker's shift from plaintext's xy
            cipherletter_xy = ((input_xy[1] + m_shifts[1]) % 6, (input_xy[0] + m_shifts[0]) % 6)
            # Append the letter
            result += s_box[cipherletter_xy[0]][cipherletter_xy[1]]
            # Shift the s_box and marker for next round
            s_box, marker = shift_s_box(s_box, marker, input_xy, s_box[cipherletter_xy[0]][cipherletter_xy[1]])
        else:
            # Compute xy of the plaintext letter by subtracting marker's shift from ciphertexts's xy
            plainletter_xy = ((input_xy[0] - m_shifts[0]) % 6, (input_xy[1] - m_shifts[1]) % 6, )
            # Append the letter
            result += s_box[plainletter_xy[1]][plainletter_xy[0]]
            # Shift the s_box and marker for next round
            s_box, marker = shift_s_box(s_box, marker, plainletter_xy, s_box[input_xy[1]][input_xy[0]])
    return result
