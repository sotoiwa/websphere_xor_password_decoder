# Decode and Encode WebSphere XOR Password
# Base code from: https://gist.github.com/metall0id/bb3e9bab2b7caee90cb7
#                 https://github.com/interference-security/scripts-tools-shells/

import base64
import argparse

parser = argparse.ArgumentParser(description='WebSphere XOR Password Decoder/Encoder')
parser.add_argument('-e', '--encode', help='Encode password', action='store_true')
parser.add_argument('-d', '--decode', help='Decode password', action='store_true')
parser.add_argument('password', help='Password to decode/encode')
args = parser.parse_args()

return_data = ''

if args.password:
    if args.encode:
        try:
            for character in args.password:
                # 1文字ずつ'_'と排他的論理和をとる
                return_data += chr(ord(character) ^ ord('_'))
            # 結果の文字列をバイト列にしてからbase64エンコード
            return_data = base64.b64encode(return_data.encode('utf-8'))
            print('Decoded Password: {}'.format(args.password))
            # バイト列を文字列にして表示
            print('Encoded Password: {{xor}}{}'.format(return_data.decode('utf-8')))
        except Exception as e:
            print('Exception: ') + str(e)
    elif args.decode:
        try:
            if args.password.startswith('{xor}'):
                args.password = args.password.replace('{xor}', '')
            # 文字列をバイト列にしてから、base64をデコードし、文字列にする
            for character in base64.b64decode(args.password.encode('utf-8')).decode('utf-8'):
                return_data += chr(ord(character) ^ ord('_'))
            print('Encoded Password: {{xor}}{}'.format(args.password))
            print('Decoded Password: {}'.format(return_data))
        except Exception as e:
            print('Exception: ') + str(e)
    else:
        parser.print_help()
else:
    parser.print_help()
