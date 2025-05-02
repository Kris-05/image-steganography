import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from werkzeug.utils import secure_filename
from PIL import Image
import numpy as np
import cv2
import pywt
from io import BytesIO
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
import base64
import traceback

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

EMAIL_CONFIG = {
    'host': 'smtp.gmail.com',
    'port': 587,
    'username': 'skismyfrnd@gmail.com',
    'password': 'wbwz gcxy ahsk yvlz',
    'from': 'skismyfrnd@gmail.com'
}

# Steganography functions
def lsb_encode(image_path, message, key):
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    
    width, height = img.size
    pixels = np.array(img)

    binary_msg = ''.join([format(ord(c), '08b') for c in message])
    binary_msg += '1111111111111110'  
    
    if len(binary_msg) > width * height * 3:
        raise ValueError("Message too large for image")
    
    # Apply key as a simple XOR mask to the message
    key_binary = ''.join([format(ord(c), '08b') for c in key])
    key_index = 0
    
    msg_index = 0
    for i in range(height):
        for j in range(width):
            for k in range(3):  
                if msg_index < len(binary_msg):
                    key_bit = int(key_binary[key_index % len(key_binary)])
                    msg_bit = int(binary_msg[msg_index]) ^ key_bit
                    
                    pixels[i, j, k] = (pixels[i, j, k] & 0xFE) | msg_bit
                    msg_index += 1
                    key_index += 1
    
    encoded_img = Image.fromarray(pixels)
    return encoded_img

def lsb_decode(image_path, key):
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    
    pixels = np.array(img)
    width, height = img.size
    
    binary_msg = ''
    key_binary = ''.join([format(ord(c), '08b') for c in key])
    key_index = 0
    
    for i in range(height):
        for j in range(width):
            for k in range(3): 
                lsb = pixels[i, j, k] & 1

                key_bit = int(key_binary[key_index % len(key_binary)])
                decoded_bit = lsb ^ key_bit
                
                binary_msg += str(decoded_bit)
                key_index += 1

    end_marker = '1111111111111110'
    if end_marker in binary_msg:
        binary_msg = binary_msg[:binary_msg.index(end_marker)]
   
    message = ''
    for i in range(0, len(binary_msg), 8):
        byte = binary_msg[i:i+8]
        if len(byte) == 8:
            message += chr(int(byte, 2))
    
    return message


def zigzag_index(k):
    # Simple zigzag pattern for mid-frequency coefficients
    if k == 1: return (0, 1)
    if k == 2: return (1, 0)
    if k == 3: return (2, 0)
    if k == 4: return (1, 1)
    if k == 5: return (0, 2)
    if k == 6: return (0, 3)
    if k == 7: return (1, 2)
    if k == 8: return (2, 1)
    if k == 9: return (3, 0)
    if k == 10: return (4, 0)
    if k == 11: return (3, 1)
    if k == 12: return (2, 2)
    if k == 13: return (1, 3)
    if k == 14: return (0, 4)
    if k == 15: return (0, 5)
    return (1, 4)


def dct_encode(image_path, message, key):
    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        raise ValueError("Could not read image")
    
    # Resize to multiple of 8 for DCT
    height, width = img.shape
    img = cv2.resize(img, (width - width % 8, height - height % 8))
    
    # Convert message to binary with key XOR
    binary_msg = ''.join([format(ord(c), '08b') for c in message])
    binary_msg += '1111111111111110' 
    
    key_binary = ''.join([format(ord(c), '08b') for c in key])
    key_index = 0

    blocks = []
    for i in range(0, img.shape[0], 8):
        for j in range(0, img.shape[1], 8):
            block = img[i:i+8, j:j+8].astype(np.float32)
            dct_block = cv2.dct(block)
            blocks.append(dct_block)

    msg_index = 0
    for block in blocks:
        if msg_index >= len(binary_msg):
            break
        
        # Embed in mid-frequency coefficients (zigzag order)
        for k in range(1, min(16, len(binary_msg) - msg_index + 1)):
            i, j = zigzag_index(k)
            
            # XOR with key bit
            key_bit = int(key_binary[key_index % len(key_binary)])
            msg_bit = int(binary_msg[msg_index]) ^ key_bit
       
            quantized = int(round(block[i, j] / 10))
            block[i, j] = (quantized & ~1) | msg_bit  
            block[i, j] *= 10 
            
            msg_index += 1
            key_index += 1
    
    # Inverse DCT
    encoded_img = np.zeros_like(img, dtype=np.float32)
    block_index = 0
    for i in range(0, img.shape[0], 8):
        for j in range(0, img.shape[1], 8):
            block = blocks[block_index]
            idct_block = cv2.idct(block)
            encoded_img[i:i+8, j:j+8] = idct_block
            block_index += 1

    encoded_img = np.clip(encoded_img, 0, 255).astype(np.uint8)
    return Image.fromarray(encoded_img)

def dct_decode(image_path, key):
    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        raise ValueError("Could not read image")
    
    # Resize to multiple of 8 for DCT
    height, width = img.shape
    img = cv2.resize(img, (width - width % 8, height - height % 8))
    
    # Apply DCT to 8x8 blocks
    blocks = []
    for i in range(0, img.shape[0], 8):
        for j in range(0, img.shape[1], 8):
            block = img[i:i+8, j:j+8].astype(np.float32)
            dct_block = cv2.dct(block)
            blocks.append(dct_block)
    
    binary_msg = ''
    key_binary = ''.join([format(ord(c), '08b') for c in key])
    key_index = 0
    
    # Extract message from mid-frequency coefficients
    for block in blocks:
        for k in range(1, 16):
            i, j = zigzag_index(k)
            
            quantized = int(round(block[i, j] / 10))
            bit = quantized & 1

            key_bit = int(key_binary[key_index % len(key_binary)])
            decoded_bit = bit ^ key_bit
            
            binary_msg += str(decoded_bit)
            key_index += 1

    end_marker = '1111111111111110'
    if end_marker in binary_msg:
        binary_msg = binary_msg[:binary_msg.index(end_marker)]

    message = ''
    for i in range(0, len(binary_msg), 8):
        byte = binary_msg[i:i+8]
        if len(byte) == 8:
            message += chr(int(byte, 2))
    
    return message

def dwt_encode(image_path, message, key):
    try:
        img = cv2.imread(image_path)
        if img is None:
            raise ValueError("Could not read image file")
            
        if len(img.shape) == 3:
            img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # Ensure image dimensions are suitable for 2-level DWT
        height, width = img.shape
        new_height = height - (height % 4)
        new_width = width - (width % 4)
        img = cv2.resize(img, (new_width, new_height))

        binary_msg = ''.join([format(ord(c), '08b') for c in message])
        binary_msg += '1111111111111110' 
        
        key_binary = ''.join([format(ord(c), '08b') for c in key])
        key_index = 0
        
        # Perform 2-level DWT
        coeffs = pywt.wavedec2(img, 'haar', level=2)
        cA2, (cH2, cV2, cD2), (cH1, cV1, cD1) = coeffs
        
        # Embed message in horizontal detail coefficients (cH1)
        msg_index = 0
        for i in range(cH1.shape[0]):
            for j in range(cH1.shape[1]):
                if msg_index >= len(binary_msg):
                    break

                key_bit = int(key_binary[key_index % len(key_binary)])
                msg_bit = int(binary_msg[msg_index]) ^ key_bit

                cH1[i, j] = cH1[i, j] * 0.99 + msg_bit * 0.1
                
                msg_index += 1
                key_index += 1
        
        # Reconstruct image
        coeffs = (cA2, (cH2, cV2, cD2), (cH1, cV1, cD1))
        encoded_img = pywt.waverec2(coeffs, 'haar')
        
        # Normalize and convert to uint8
        encoded_img = np.clip(encoded_img, 0, 255)
        encoded_img = encoded_img.astype(np.uint8)
        
        return Image.fromarray(encoded_img)
    
    except Exception as e:
        print(f"DWT Encode Error: {str(e)}")
        raise

def dwt_decode(image_path, key):
    try:
        img = cv2.imread(image_path)
        if img is None:
            raise ValueError("Could not read image file")
            
        if len(img.shape) == 3:
            img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        coeffs = pywt.wavedec2(img, 'haar', level=2)
        cA2, (cH2, cV2, cD2), (cH1, cV1, cD1) = coeffs
        
        binary_msg = ''
        key_binary = ''.join([format(ord(c), '08b') for c in key])
        key_index = 0
        
        # Extract message from horizontal detail coefficients (cH1)
        for i in range(cH1.shape[0]):
            for j in range(cH1.shape[1]):
                bit = 1 if cH1[i, j] > 0.5 else 0

                key_bit = int(key_binary[key_index % len(key_binary)])
                decoded_bit = bit ^ key_bit
                
                binary_msg += str(decoded_bit)
                key_index += 1

        end_marker = '1111111111111110'
        if end_marker in binary_msg:
            binary_msg = binary_msg[:binary_msg.index(end_marker)]

        message = ''
        for i in range(0, len(binary_msg), 8):
            byte = binary_msg[i:i+8]
            if len(byte) == 8:
                message += chr(int(byte, 2))
        
        return message
    
    except Exception as e:
        print(f"DWT Decode Error: {str(e)}")
        raise

def send_email(to_email, subject, body, image_path, technique, key):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_CONFIG['from']
    msg['To'] = to_email
    msg['Subject'] = subject

    email_body = f"""
    {body}
    
    Technique used: {technique}
    Secret Key: {key}
    
    This email contains an encoded image with your secret message.
    """
    
    msg.attach(MIMEText(email_body, 'plain'))

    with open(image_path, 'rb') as f:
        img = MIMEImage(f.read())
        img.add_header('Content-Disposition', 'attachment', filename="secret_image.png")
        msg.attach(img)

    try:
        with smtplib.SMTP(EMAIL_CONFIG['host'], EMAIL_CONFIG['port']) as server:
            server.starttls()
            server.login(EMAIL_CONFIG['username'], EMAIL_CONFIG['password'])
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


def msgtobinary(msg):
    """Convert different input types to binary format"""
    if isinstance(msg, str):
        return ''.join([format(ord(i), "08b") for i in msg])
    elif isinstance(msg, (bytes, np.ndarray)):
        return [format(i, "08b") for i in msg]
    elif isinstance(msg, (int, np.uint8)):
        return format(msg, "08b")
    else:
        raise TypeError(f"Input type not supported: {type(msg)}")

def KSA(key):
    key_length = len(key)
    S = list(range(256)) 
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def PRGA(S, n):
    i = 0
    j = 0
    key = []
    while n > 0:
        n = n - 1
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        key.append(K)
    return key

def preparing_key_array(s):
    return [ord(c) for c in s]

def encryption(plaintext, key):
    key = preparing_key_array(key)
    S = KSA(key)
    keystream = np.array(PRGA(S, len(plaintext)))
    plaintext = np.array([ord(i) for i in plaintext])
    cipher=keystream^plaintext
    ctext=''
    for c in cipher:
        ctext=ctext+chr(c)
    return ctext

def decryption(ciphertext, key):
    key=preparing_key_array(key)
    S=KSA(key)
    keystream=np.array(PRGA(S,len(ciphertext)))
    ciphertext=np.array([ord(i) for i in ciphertext])
    decoded=keystream^ciphertext
    dtext=''
    for c in decoded:
        dtext=dtext+chr(c)
    return dtext

def embed(frame, data):
    if len(data) == 0: 
        raise ValueError('Data entered to be encoded is empty')

    data += '*^*^*'
    binary_data = msgtobinary(data)
    length_data = len(binary_data)
    
    index_data = 0
    
    if len(frame.shape) == 2:  # grayscale
        frame = cv2.cvtColor(frame, cv2.COLOR_GRAY2RGB)
    elif frame.shape[2] == 4:  # RGBA
        frame = cv2.cvtColor(frame, cv2.COLOR_RGBA2RGB)
    else:
        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

    frame = frame.tolist()
    
    for i in range(len(frame)):
        for j in range(len(frame[i])):
            pixel = frame[i][j]
            r, g, b = pixel  
            r_bin = msgtobinary(r)
            g_bin = msgtobinary(g)
            b_bin = msgtobinary(b)
            
            if index_data < length_data:
                pixel[0] = int(r_bin[:-1] + binary_data[index_data], 2)
                index_data += 1
            if index_data < length_data:
                pixel[1] = int(g_bin[:-1] + binary_data[index_data], 2)
                index_data += 1
            if index_data < length_data:
                pixel[2] = int(b_bin[:-1] + binary_data[index_data], 2)
                index_data += 1
            if index_data >= length_data:
                break
        if index_data >= length_data:
            break

    
    return np.array(frame, dtype=np.uint8)



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/receiver')
def receiver():
    return render_template('receiver.html')

def extract(frame, max_bits=100000):
    """Extract hidden message from frame with improved reliability"""
    data_binary = ""

    if len(frame.shape) == 2:  # grayscale
        frame = cv2.cvtColor(frame, cv2.COLOR_GRAY2RGB)
    elif frame.shape[2] == 4:  # RGBA
        frame = cv2.cvtColor(frame, cv2.COLOR_RGBA2RGB)
    else:
        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    
    frame = frame.tolist()
    
    bit_count = 0
    for row in frame:
        for pixel in row:
            try:
                r, g, b = pixel[0], pixel[1], pixel[2]
                data_binary += str(r & 1)
                data_binary += str(g & 1)
                data_binary += str(b & 1)
                bit_count += 3

                if bit_count % 24 == 0:  
                    bytes_data = [data_binary[i:i+8] for i in range(0, len(data_binary), 8)]
                    message = ""
                    for byte in bytes_data:
                        if len(byte) == 8:
                            message += chr(int(byte, 2))
                            if message.endswith("*^*^*"):
                                return message[:-5]  

                if bit_count > max_bits:
                    return "No message found"
                    
            except Exception as e:
                print(f"Error processing pixel: {e}")
                continue
    
    return "No message found"

@app.route('/video_encode', methods=['POST'])
def video_encode():
    if 'video' not in request.files:
        flash('No video file selected')
        return redirect(url_for('index'))
    
    file = request.files['video']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('index'))
    
    try:
        temp_filename = f"temp_{secrets.token_hex(8)}.mp4"
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
        file.save(temp_path)
        
        message = request.form.get('message', '')
        frame_num = int(request.form.get('frame_number', 1))
        key = request.form.get('key', '')
        
        print(f"\n=== ENCODING STARTED ===\nMessage: {message}\nFrame: {frame_num}\nKey: {key}")

        cap = cv2.VideoCapture(temp_path)
        if not cap.isOpened():
            raise ValueError("Could not open video file")

        # Get video properties
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        if frame_num < 1 or frame_num > total_frames:
            flash(f'Frame number must be between 1 and {total_frames}')
            return redirect(url_for('index'))

        frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        fps = cap.get(cv2.CAP_PROP_FPS)

        # Get the frame to modify
        cap.set(cv2.CAP_PROP_POS_FRAMES, frame_num - 1)
        ret, frame = cap.read()
        if not ret:
            flash('Could not read the specified frame')
            return redirect(url_for('index'))
        
        print(f"Original frame shape: {frame.shape}")
        
        # Encrypt and embed
        encrypted_msg = encryption(message, key)
        print(f"Encrypted message: {encrypted_msg}")
        modified_frame = embed(frame, encrypted_msg)
        print(f"Modified frame shape: {modified_frame.shape}")

        # Create output video
        output_filename = f"stego_{secrets.token_hex(8)}.avi"
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
        fourcc = cv2.VideoWriter_fourcc(*'XVID')
        out = cv2.VideoWriter(output_path, fourcc, fps, (frame_width, frame_height))
        
        # Rewrite all frames with modified frame
        cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
        current_frame = 0
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            current_frame += 1
            if current_frame == frame_num:
                out.write(modified_frame)
            else:
                out.write(frame)
        
        print("=== ENCODING COMPLETED ===")
        return render_template('index.html', 
                            encoded_video=output_filename,
                            frame_number=frame_num,
                            key=key,
                            steg_type='video',
                            show_result=True)
    
    except Exception as e:
        print(f"ENCODING ERROR: {str(e)}")
        print(traceback.format_exc())
        flash(f'Error during video encoding: {str(e)}')
        return redirect(url_for('index'))
    finally:
        if 'cap' in locals() and cap.isOpened():
            cap.release()
        if 'out' in locals() and out.isOpened():
            out.release()
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass
    
@app.route('/video_decode', methods=['POST'])
def video_decode():
    if 'video' not in request.files:
        flash('No video file selected')
        return redirect(url_for('receiver'))
    
    file = request.files['video']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('receiver'))
    
    # Create temp file
    temp_filename = f"temp_{secrets.token_hex(8)}.mp4"
    temp_path = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
    file.save(temp_path)
    
    try:
        # Get parameters
        frame_num = int(request.form.get('frame_number', 1))
        key = request.form.get('key', '')
        
        print(f"\n=== DECODING STARTED ===\nFrame: {frame_num}\nKey: {key}")
        
        # Open video
        cap = cv2.VideoCapture(temp_path)
        if not cap.isOpened():
            flash('Could not open video file')
            return redirect(url_for('receiver'))
        
        # Get video properties
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        if frame_num < 1 or frame_num > total_frames:
            flash(f'Frame number must be between 1 and {total_frames}')
            return redirect(url_for('receiver'))

        # Seek to frame
        cap.set(cv2.CAP_PROP_POS_FRAMES, frame_num - 1)
        ret, frame = cap.read()
        
        if not ret:
            flash('Could not read the specified frame')
            return redirect(url_for('receiver'))
        
        print(f"Frame shape before processing: {frame.shape}")
        
        # Extract message
        encrypted_msg = extract(frame)
        print(f"Extracted encrypted message: {encrypted_msg}")
        
        if not encrypted_msg or encrypted_msg == "No message found":
            flash('No hidden message found in the specified frame')
            return redirect(url_for('receiver'))
        
        # Decrypt message
        decrypted_msg = decryption(encrypted_msg, key)
        print(f"Decrypted message: {decrypted_msg}")
        
        # Prepare frame for display
        _, img_encoded = cv2.imencode('.png', frame)
        img_str = base64.b64encode(img_encoded).decode('utf-8')
        
        print("=== DECODING COMPLETED ===")
        return render_template('receiver.html',
                            decoded_image=img_str,
                            decoded_message=decrypted_msg,
                            steg_type='video',
                            show_result=True)
    
    except Exception as e:
        print(f"DECODING ERROR: {str(e)}")
        print(traceback.format_exc())
        flash(f'Error during decoding: {str(e)}')
    finally:
        if 'cap' in locals() and cap.isOpened():
            cap.release()
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass
    
    return redirect(url_for('receiver'))

@app.route('/decode', methods=['POST'])
def decode_file():
    if 'image' not in request.files:
        flash('No image file selected')
        return redirect(url_for('receiver'))
    
    file = request.files['image']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('receiver'))
    
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        key = request.form.get('key', 'default_key')
        technique = request.form.get('technique', 'lsb')
        
        try:
            if technique == 'lsb':
                message = lsb_decode(filepath, key)
            elif technique == 'dct':
                message = dct_decode(filepath, key)
            elif technique == 'dwt':
                message = dwt_decode(filepath, key)
            else:
                flash('Invalid technique selected')
                return redirect(url_for('receiver'))
            
            # Display the decoded image
            img = Image.open(filepath)
            buffered = BytesIO()
            img.save(buffered, format="PNG")
            img_str = base64.b64encode(buffered.getvalue()).decode('utf-8')
            
            return render_template('receiver.html', 
                                decoded_image=img_str,
                                decoded_message=message,
                                show_result=True)
        
        except Exception as e:
            flash(f'Error during decoding: {str(e)}')
            return redirect(url_for('receiver'))

@app.route('/upload', methods=['POST'])
def upload():
    if 'image' not in request.files:
        flash('No image file selected')
        return redirect(url_for('index'))
    
    file = request.files['image']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('index'))
    
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        message = request.form.get('message', '')
        key = request.form.get('key', 'default_key')
        technique = request.form.get('technique', 'lsb')
        email = request.form.get('email', None)
        
        try:
            encoded_img = None

            if technique == 'lsb':
                encoded_img = lsb_encode(filepath, message, key)
            elif technique == 'dct':
                encoded_img = dct_encode(filepath, message, key)
            elif technique == 'dwt':
                encoded_img = dwt_encode(filepath, message, key)
            else:
                flash('Invalid technique selected')
                return redirect(url_for('index'))
            
            # Check if encoding was successful
            if encoded_img is None:
                raise ValueError("Encoding failed - no image was produced")

            encoded_filename = f"encoded_{secrets.token_hex(8)}.png"
            encoded_filepath = os.path.join(app.config['UPLOAD_FOLDER'], encoded_filename)
            encoded_img.save(encoded_filepath)

            if email:
                send_success = send_email(
                    email, 
                    "Steganography Image", 
                    "Here is your secret image!", 
                    encoded_filepath, 
                    technique, 
                    key
                )
                if not send_success:
                    flash('Failed to send email, but image was encoded successfully')

            buffered = BytesIO()
            encoded_img.save(buffered, format="PNG")
            img_str = base64.b64encode(buffered.getvalue()).decode('utf-8')
            
            return render_template('index.html', 
                               encoded_image=img_str,
                               technique=technique,
                               key=key,
                               steg_type='image',
                               email=email,
                               show_result=True)
            
        except Exception as e:
            flash(f'Error during encoding: {str(e)}')
            return redirect(url_for('index'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True)