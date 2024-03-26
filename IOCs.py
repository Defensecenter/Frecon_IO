import requests
import os
from datetime import datetime, timedelta

# Función para determinar el tipo de hash basado en su longitud
def identify_hash_type(hash_string):
    if len(hash_string) == 32:
        return "MD5"
    elif len(hash_string) == 40:
        return "SHA1"
    elif len(hash_string) == 64:
        return "SHA256"
    else:
        return "Unknown"

# Función para cargar los datos existentes de un archivo de texto
def load_existing_data(filename):
    try:
        with open(filename, "r", encoding='utf-8') as file:
            return set(line.strip() for line in file)
    except FileNotFoundError:
        return set()

# Función para actualizar el archivo de texto con nuevos datos
def update_main_txt_file(ioc_type, new_data):
    main_filename = f"IOC_{ioc_type}.txt"
    existing_data = load_existing_data(main_filename)

    new_unique_data = new_data - existing_data

    with open(main_filename, "a", encoding='utf-8') as file:
        for data in new_unique_data:
            file.write(f"{data}\n" if isinstance(data, str) else ",".join(data) + "\n")

# Función para realizar la solicitud y guardar los datos en archivos de texto
def fetch_and_save_ioc_data(ioc_type):
    url = "https://api.fortirecon.forticloud.com/aci/f6beebd4-b39d-4d58-ad65-e3c4143d8471/iocs"
    headers = {
        "accept": "application/json",
        "Authorization": "88gkjDQhKQ9HGhHK0ali2rfu3kclGjyH"
    }
    start_date = (datetime.now() - timedelta(days=4)).strftime('%Y-%m-%d')
    current_date = datetime.now().strftime('%d_%m_%Y')

    page = 1
    total_pages = 1

    new_data = set()

    while page <= total_pages:
        params = {
            "ioc_type": ioc_type,
            "start_date": start_date,
            "size": 500,
            "page": page
        }

        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            total_pages = (data['total'] - 1) // 500 + 1

            for hit in data.get('hits', []):
                ioc_data = hit['ioc']
                if ioc_type == "HASH":
                    hash_type = identify_hash_type(ioc_data)
                    new_data.add((hash_type, ioc_data))
                else:
                    new_data.add(ioc_data)

            page += 1
        else:
            print(f"Error en la solicitud para {ioc_type} en la página {page}: ", response.status_code)
            break

    date_filename = f"IOC_{ioc_type}_{current_date}.txt"
    with open(date_filename, "w", encoding='utf-8') as file:
        for data in new_data:
            file.write(f"{data}\n" if isinstance(data, str) else ",".join(data) + "\n")

    update_main_txt_file(ioc_type, new_data)

    # Eliminar el archivo con fecha
    if os.path.exists(date_filename):
        os.remove(date_filename)

    print(f"Datos de {ioc_type} actualizados exitosamente y archivo con fecha eliminado.")

ioc_types = ["URL", "HASH", "DOMAIN", "IP", "adversary", "cve", "file_name", "email", "file_path", "registry_key"]
for ioc_type in ioc_types:
    fetch_and_save_ioc_data(ioc_type)

# Función para cargar los datos existentes de un archivo de texto
def load_existing_hashes(filename):
    try:
        with open(filename, "r", encoding='utf-8') as file:
            return set(line.strip() for line in file)
    except FileNotFoundError:
        return set()

# Función para actualizar un archivo de texto con nuevos hashes
def update_hash_file(filename, new_hashes):
    existing_hashes = load_existing_hashes(filename)

    with open(filename, "a", encoding='utf-8') as file:
        for hash_value in new_hashes:
            if hash_value not in existing_hashes:
                file.write(f"{hash_value}\n")

# Función para procesar el archivo IOC_HASH y actualizar los archivos individuales
def process_and_update_hash_files(hash_file):
    new_md5_hashes = set()
    new_sha1_hashes = set()
    new_sha256_hashes = set()

    with open(hash_file, "r", encoding='utf-8') as file:
        for line in file:
            if line:
                hash_type, hash_value = line.strip().split(',')
                if hash_type == "MD5":
                    new_md5_hashes.add(hash_value)
                elif hash_type == "SHA1":
                    new_sha1_hashes.add(hash_value)
                elif hash_type == "SHA256":
                    new_sha256_hashes.add(hash_value)

    update_hash_file("IOC_MD5.txt", new_md5_hashes)
    update_hash_file("IOC_SHA1.txt", new_sha1_hashes)
    update_hash_file("IOC_SHA256.txt", new_sha256_hashes)
    print("Hash files have been updated successfully.")

# Llamar a la función con el archivo IOC_HASH.txt
process_and_update_hash_files("IOC_HASH.txt")
