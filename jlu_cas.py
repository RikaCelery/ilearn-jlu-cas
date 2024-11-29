import requests
from urllib.parse import quote, unquote
from bs4 import BeautifulSoup
import time
import base64
import json

username = 'username'
password = 'password'

class JLU:
    @staticmethod
    def str_enc(data, first_key, second_key, third_key):
        leng = len(data)
        enc_data = ""
        first_key_bt, second_key_bt, third_key_bt = None, None, None
        first_length, second_length, third_length = 0, 0, 0

        if first_key:
            first_key_bt = JLU.get_key_bytes(first_key)
            first_length = len(first_key_bt)
        if second_key:
            second_key_bt = JLU.get_key_bytes(second_key)
            second_length = len(second_key_bt)
        if third_key:
            third_key_bt = JLU.get_key_bytes(third_key)
            third_length = len(third_key_bt)

        if leng > 0:
            if leng < 4:
                bt = JLU.str_to_bt(data)
                if first_key and second_key and third_key:
                    temp_bt = bt
                    for x in range(first_length):
                        temp_bt = JLU.enc(temp_bt, first_key_bt[x])
                    for y in range(second_length):
                        temp_bt = JLU.enc(temp_bt, second_key_bt[y])
                    for z in range(third_length):
                        temp_bt = JLU.enc(temp_bt, third_key_bt[z])
                    enc_byte = temp_bt
                elif first_key and second_key:
                    temp_bt = bt
                    for x in range(first_length):
                        temp_bt = JLU.enc(temp_bt, first_key_bt[x])
                    for y in range(second_length):
                        temp_bt = JLU.enc(temp_bt, second_key_bt[y])
                    enc_byte = temp_bt
                elif first_key:
                    temp_bt = bt
                    for x in range(first_length):
                        temp_bt = JLU.enc(temp_bt, first_key_bt[x])
                    enc_byte = temp_bt
                else:
                    enc_byte = bt
                enc_data = JLU.bt64_to_hex(enc_byte)
            else:
                iterator = leng // 4
                remainder = leng % 4
                for i in range(iterator):
                    temp_data = data[i*4:i*4+4]
                    temp_byte = JLU.str_to_bt(temp_data)
                    if first_key and second_key and third_key:
                        temp_bt = temp_byte
                        for x in range(first_length):
                            temp_bt = JLU.enc(temp_bt, first_key_bt[x])
                        for y in range(second_length):
                            temp_bt = JLU.enc(temp_bt, second_key_bt[y])
                        for z in range(third_length):
                            temp_bt = JLU.enc(temp_bt, third_key_bt[z])
                        enc_byte = temp_bt
                    elif first_key and second_key:
                        temp_bt = temp_byte
                        for x in range(first_length):
                            temp_bt = JLU.enc(temp_bt, first_key_bt[x])
                        for y in range(second_length):
                            temp_bt = JLU.enc(temp_bt, second_key_bt[y])
                        enc_byte = temp_bt
                    elif first_key:
                        temp_bt = temp_byte
                        for x in range(first_length):
                            temp_bt = JLU.enc(temp_bt, first_key_bt[x])
                        enc_byte = temp_bt
                    else:
                        enc_byte = temp_byte
                    enc_data += JLU.bt64_to_hex(enc_byte)

                if remainder > 0:
                    remainder_data = data[iterator*4:]
                    temp_byte = JLU.str_to_bt(remainder_data)
                    if first_key and second_key and third_key:
                        temp_bt = temp_byte
                        for x in range(first_length):
                            temp_bt = JLU.enc(temp_bt, first_key_bt[x])
                        for y in range(second_length):
                            temp_bt = JLU.enc(temp_bt, second_key_bt[y])
                        for z in range(third_length):
                            temp_bt = JLU.enc(temp_bt, third_key_bt[z])
                        enc_byte = temp_bt
                    elif first_key and second_key:
                        temp_bt = temp_byte
                        for x in range(first_length):
                            temp_bt = JLU.enc(temp_bt, first_key_bt[x])
                        for y in range(second_length):
                            temp_bt = JLU.enc(temp_bt, second_key_bt[y])
                        enc_byte = temp_bt
                    elif first_key:
                        temp_bt = temp_byte
                        for x in range(first_length):
                            temp_bt = JLU.enc(temp_bt, first_key_bt[x])
                        enc_byte = temp_bt
                    else:
                        enc_byte = temp_byte
                    enc_data += JLU.bt64_to_hex(enc_byte)

        return enc_data

    @staticmethod
    def enc(data_byte, key_byte):
        keys = JLU.generate_keys(key_byte)
        ip_byte = JLU.init_permute(data_byte)
        ip_left = [0] * 32
        ip_right = [0] * 32
        temp_left = [0] * 32

        for k in range(32):
            ip_left[k] = ip_byte[k]
            ip_right[k] = ip_byte[32 + k]

        for i in range(16):
            for j in range(32):
                temp_left[j] = ip_left[j]
                ip_left[j] = ip_right[j]

            key = keys[i]
            temp_right = JLU.xor(JLU.p_permute(JLU.s_box_permute(
                JLU.xor(JLU.expand_permute(ip_right), key))), temp_left)
            ip_right = temp_right[:]

        final_data = [0] * 64
        for i in range(32):
            final_data[i] = ip_right[i]
            final_data[32 + i] = ip_left[i]

        return JLU.finally_permute(final_data)

    @staticmethod
    def get_key_bytes(key):
        breakpoint()
        key_bytes = []
        leng = len(key)
        iterator = leng // 4
        remainder = leng % 4
        for i in range(iterator):
            key_bytes.append(JLU.str_to_bt(key[i*4:i*4+4]))
        if remainder > 0:
            key_bytes.append(JLU.str_to_bt(key[iterator*4:]))
        return key_bytes

    @staticmethod
    def str_to_bt(s):
        leng = len(s)
        bt = [0] * 64
        if leng < 4:
            for i in range(leng):
                k = ord(s[i])
                for j in range(16):
                    pow = 1 << (15 - j)
                    bt[16*i + j] = (k // pow) % 2
            for p in range(leng, 4):
                k = 0
                for q in range(16):
                    pow = 1 << (15 - q)
                    bt[16*p + q] = (k // pow) % 2
        else:
            for i in range(4):
                k = ord(s[i])
                for j in range(16):
                    pow = 1 << (15 - j)
                    bt[16*i + j] = (k // pow) % 2
        return bt

    @staticmethod
    def bt4_to_hex(binary):
        hex_dict = {
            "0000": "0", "0001": "1", "0010": "2", "0011": "3",
            "0100": "4", "0101": "5", "0110": "6", "0111": "7",
            "1000": "8", "1001": "9", "1010": "A", "1011": "B",
            "1100": "C", "1101": "D", "1110": "E", "1111": "F"
        }
        return hex_dict[binary]

    @staticmethod
    def hex_to_bt4(hex):
        bt4_dict = {
            "0": "0000", "1": "0001", "2": "0010", "3": "0011",
            "4": "0100", "5": "0101", "6": "0110", "7": "0111",
            "8": "1000", "9": "1001", "A": "1010", "B": "1011",
            "C": "1100", "D": "1101", "E": "1110", "F": "1111"
        }
        return bt4_dict[hex]

    @staticmethod
    def byte_to_string(byte_data):
        str = ""
        for i in range(4):
            count = 0
            for j in range(16):
                pow = 1 << (15 - j)
                count += byte_data[16*i + j] * pow
            if count != 0:
                str += chr(count)
        return str

    @staticmethod
    def bt64_to_hex(byte_data):
        hex = ""
        for i in range(16):
            bt = "".join(str(b) for b in byte_data[i*4:(i+1)*4])
            hex += JLU.bt4_to_hex(bt)
        return hex

    @staticmethod
    def hex_to_bt64(hex):
        binary = ""
        for i in range(16):
            binary += JLU.hex_to_bt4(hex[i])
        return [int(b) for b in binary]

    @staticmethod
    def init_permute(original_data):
        ip_byte = [0] * 64
        for i, m, n in zip(range(4), range(1, 8, 2), range(0, 8, 2)):
            for j, k in zip(range(7, -1, -1), range(8)):
                ip_byte[i * 8 + k] = original_data[j * 8 + m]
                ip_byte[i * 8 + k + 32] = original_data[j * 8 + n]
        return ip_byte

    @staticmethod
    def expand_permute(right_data):
        ep_byte = [0] * 48
        for i in range(8):
            if i == 0:
                ep_byte[i * 6 + 0] = right_data[31]
            else:
                ep_byte[i * 6 + 0] = right_data[i * 4 - 1]
            ep_byte[i * 6 + 1] = right_data[i * 4 + 0]
            ep_byte[i * 6 + 2] = right_data[i * 4 + 1]
            ep_byte[i * 6 + 3] = right_data[i * 4 + 2]
            ep_byte[i * 6 + 4] = right_data[i * 4 + 3]
            if i == 7:
                ep_byte[i * 6 + 5] = right_data[0]
            else:
                ep_byte[i * 6 + 5] = right_data[i * 4 + 4]
        return ep_byte

    @staticmethod
    def xor(byte_one, byte_two):
        return [a ^ b for a, b in zip(byte_one, byte_two)]

    @staticmethod
    def s_box_permute(expand_byte):
        s_box_byte = [0] * 32
        s = [
            # S1
            [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
             [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
             [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
             [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

            [
                [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

            [
                [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

            [
                [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],


            [
                [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],


            [
                [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

            [
                [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

            [
                [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
                [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
        ]

        for m in range(8):
            i = expand_byte[m * 6 + 0] * 2 + expand_byte[m * 6 + 5]
            j = (expand_byte[m * 6 + 1] * 8 + expand_byte[m * 6 + 2] * 4 +
                 expand_byte[m * 6 + 3] * 2 + expand_byte[m * 6 + 4])
            binary = f"{s[m][i][j]:04b}"
            s_box_byte[m * 4 + 0] = int(binary[0])
            s_box_byte[m * 4 + 1] = int(binary[1])
            s_box_byte[m * 4 + 2] = int(binary[2])
            s_box_byte[m * 4 + 3] = int(binary[3])

        return s_box_byte

    @staticmethod
    def p_permute(s_box_byte):
        p_box_permute = [0] * 32
        p_table = [15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9,
                   1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24]

        for i in range(32):
            p_box_permute[i] = s_box_byte[p_table[i]]

        return p_box_permute

    @staticmethod
    def finally_permute(end_byte):
        fp_byte = [0] * 64
        fp_table = [39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
                    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28,
                    35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26,
                    33, 1, 41, 9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24]

        for i in range(64):
            fp_byte[i] = end_byte[fp_table[i]]

        return fp_byte

    @staticmethod
    def generate_keys(key_byte):
        key = [0] * 56
        keys = [[0] * 48 for _ in range(16)]

        loop = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

        for i in range(7):
            for j, k in enumerate(range(7, -1, -1)):
                key[i * 8 + j] = key_byte[8 * k + i]

        for i in range(16):
            temp_left = temp_right = 0
            for j in range(loop[i]):
                temp_left = key[0]
                temp_right = key[28]
                for k in range(27):
                    key[k] = key[k + 1]
                    key[28 + k] = key[29 + k]
                key[27] = temp_left
                key[55] = temp_right

            temp_key = [0] * 48
            key_table = [13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3,
                         25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39,
                         50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31]

            for m in range(48):
                temp_key[m] = key[key_table[m]]

            keys[i] = temp_key
        return keys


sess = requests.session()
sess.headers.update({
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',

})
URL = 'https://cas.jlu.edu.cn/tpass/login?service=https%3A%2F%2Fjwcidentity.jlu.edu.cn%2Fiplat-pass-jlu%2FthirdLogin%2Fjlu%2Flogin'
sess.proxies={"https":"http://127.0.0.1:6725"}
r = sess.get(URL,verify=False)
# sess.close()
r.cookies.get('tpasssessionid')
html = BeautifulSoup(r.text)
nonce = html.select_one('#lt').attrs['value']
encoded = JLU.str_enc(username+password+nonce, "1", "2", "3")
data = {
    "rsa": encoded,
    "ul": "9",
    "pl": "12",
    "sl": 0,
    "lt": nonce,
    "execution": "e1s1",
    "_eventId": "submit",
}
sess.headers.update(sess.headers)

r1 = sess.post(URL, data=data, verify=False, allow_redirects=True, cookies=r.cookies, headers={'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36', 'Accept-Encoding': 'gzip, deflate, br, zstd', 'Accept': '*/*', 'Connection': 'keep-alive'
                                                                                                   })
print(r1.text)
html_cas = BeautifulSoup(r1.text)
cas_username = html_cas.select_one('#username').attrs['value']
cas_password = html_cas.select_one('#password').attrs['value']
ts = int(time.time()*1000)
r2 = sess.get("https://ilearn.jlu.edu.cn/cas-server/login",
              params={
                  "service": "https://ilearntec.jlu.edu.cn/",
                  "get-lt": "true",
                  "callback": "jsonpcallback",
                  "n": ts+1,
                  "_": ts,
              }, verify=False, allow_redirects=False)

cas_return = json.loads(r2.text[14:-2])
print(cas_return, cas_username, cas_password)
ts = int(time.time()*1000)
r3 = sess.get("https://ilearn.jlu.edu.cn/cas-server/login",
              params={
                  "service": "https://ilearntec.jlu.edu.cn/",
                  "username": cas_username,
                  "password": base64.b64encode(cas_password.encode()),
                  "isajax": "true",
                  "isframe": "true",
                  "callback": "logincallback",
                  "lt": cas_return['lt'],
                  "type": "pwd",
                  "execution": cas_return['execution'],
                  "_eventId": "submit",
                  "_": ts,
              }, verify=False, allow_redirects=False)
cas_ilearn_return = json.loads(r3.text[14:-4])
print(cas_ilearn_return)
# if login ok
r4 = sess.get("https://ilearntec.jlu.edu.cn/",
              verify=False, allow_redirects=True)
print(r4.text)
r5 = sess.get("https://ilearntec.jlu.edu.cn/coursecenter/main/index",
              params={"ticket": cas_ilearn_return['ticket']}, verify=False)
for c in sess.cookies:
    print(f'{c.name}={c.value}', c.domain)

JLU.str_enc("a", "1", "2", "3")
JLU.str_enc("abc", "1", "2", "3")
JLU.str_enc("asjdf", "1", "2", "3")
JLU.str_enc("aaodsajionn", "1", "2", "3")


JLU.str_enc("a", "1", "2", "")
JLU.str_enc("abc", "1", "2", "")
JLU.str_enc("asjdf", "1", "2", "")
JLU.str_enc("afhueygwfyubavceg", "1", "2", "")
JLU.str_enc("aaodsajionn", "1", "2", "")

JLU.str_enc("a", "1", "", "")
JLU.str_enc("abc", "1", "", "")
JLU.str_enc("asjdf", "1", "", "")
JLU.str_enc("aaodsajionn", "1", "", "")

JLU.str_enc("asjdf", "12345678", "234abc", "33456776")
JLU.str_enc("abc", "12345678", "234abc", "334567")
JLU.str_enc("aaodsajionn", "1234567812345678", "234abc234abc", "334567334567")

