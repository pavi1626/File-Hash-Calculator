from flask import Flask, request, render_template, send_from_directory, url_for
import os
import hashlib
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
import shutil
import time

UPLOAD_FOLDER = 'uploads'

app = Flask(__name__, template_folder='templates') 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER 

def calculate_hash(file_path, algorithm):
    hash_object = getattr(hashlib, algorithm.lower())()  
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b''):
            hash_object.update(chunk)
    return hash_object.hexdigest()

def generate_key():
    key = Fernet.generate_key()
    return key

def encrypt_file(key, input_file, output_file):
    start_time = time.time()
    with open(input_file, 'rb') as f:
        data = f.read()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)
    with open(output_file, 'wb') as f:
        f.write(encrypted)
    end_time = time.time()
    encryption_time = end_time - start_time
    return encryption_time

def decrypt_file(key, input_file, output_file):
    start_time = time.time()
    with open(input_file, 'rb') as f:
        data = f.read()
    fernet = Fernet(key)
    decrypted = fernet.decrypt(data)
    with open(output_file, 'wb') as f:
        f.write(decrypted)
    end_time = time.time()
    decryption_time = end_time - start_time
    return decryption_time

file_sizes = []
encryption_times = []
decryption_times = []

def is_valid_filename(filename):
    # Add your validation logic here
    return True

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file_upload' in request.files:
            
            file = request.files['file_upload']
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            

            original_hash = calculate_hash(file_path, 'sha256')
            key = generate_key()
            key_str = key.decode()   
            file_size = os.path.getsize(file_path)
            encryption_time = encrypt_file(key, file_path, 'encrypted.enc')
            shutil.move('encrypted.enc', os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted.enc'))
            
            
            file_sizes.append(file_size)
            encryption_times.append(encryption_time)

            print("File Size:", file_size)
            print("Encryption Time:", encryption_time)
            

            results = f"""
                Original File Hash (SHA-256): {original_hash} <br>
                Encryption Key: {key_str} <br>  
                Encryption Status: Success (Fernet) <br>
                path = {filename} <br>

                File size : {file_size} bytes<br>

                Encryption time : {encryption_time}
                
                <a href="{url_for('download_file', filename='encrypted.enc')}">Download Encrypted File</a> <br> 
            """

            return render_template('index.html', results=results, file_sizes=file_sizes, encryption_times=encryption_times, decryption_times=decryption_times)
    else:
        return render_template('index.html')


@app.route('/download_file', methods=['GET'])
def download_file():
    filename = request.args.get('filename')  
    print(filename)

    
    if filename is not None and is_valid_filename(filename):  
        uploads_path = app.config['UPLOAD_FOLDER']   
        file_path = os.path.join(uploads_path, filename)
        print(filename)

        if os.path.exists(file_path):
            print(filename)
            return send_from_directory(directory=uploads_path, path=filename, as_attachment=True)
        else:
            print(filename)
            return "File not found", 404   
    else:
        print(filename)
        return "Invalid filename", 400  

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'encrypted_file' in request.files:
        
        file = request.files['encrypted_file']
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        print(app.config['UPLOAD_FOLDER'])
        print(file_path)
        file.save(file_path)

        

        original_hash = request.form.get('original_hash', '')

        kay = request.form.get('key')
        print(kay)

        if 'key' in request.form:  
            submitted_key = request.form['key'].encode()  
            print("Original Hash (from form):", original_hash) 

            

            
            try:
                file_size = os.path.getsize(file_path)
                decryption_time = decrypt_file(submitted_key, file_path, 'decrypted.txt')

                file_sizes.append(file_size)
                decryption_times.append(decryption_time)
                shutil.move('decrypted.txt', os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted.txt'))
                print("Decryption function completed...")

                #new_hash = calculate_hash('decrypted.txt', 'sha256')
                new_hash = calculate_hash(os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted.txt'), 'sha256')
                

                print("Before retrieving original hash...")  # Add this line
                #original_hash = retrieve_original_hash()  
                print("... After retrieving original hash")  # Add this line

                print("Original hash (retrieved):", original_hash)  
                print("New hash:", new_hash) 
                print("Hashes match:", original_hash == new_hash)

                print("File Size:", file_size)
                print("Decryption Time:", decryption_time) 
            

               


                results = f""" 
                    Original File Hash (SHA-256): {original_hash} <br> 
                    Decryption Status: Success <br>
                    New File Hash (SHA-256): {new_hash} <br>

                    File size : {file_size} bytes<br>
                    Decryption Time : {decryption_time} <br>

                    Hash Comparison: {'Hashes Match' if original_hash == new_hash else 'Hashes DO NOT Match'}
                 """
                print("Rendering decrypt results:", results)

                return render_template('index.html', results=results, file_sizes=file_sizes, encryption_times=encryption_times, decryption_times=decryption_times)
            except Exception as e:
                return render_template('index.html', error="Decryption failed. Error: {}".format(e))
        else:
            return render_template('index.html', error="Encryption key not provided.")
    else:
        return render_template('index.html', error="No encrypted file provided.")
    

  


if __name__ == '__main__':
    app.run(debug=True) 
