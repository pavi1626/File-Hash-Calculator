import argparse
import hashlib
import os
from tqdm import tqdm

def calculate_hash(file_path, algorithm):
    hash_object = getattr(hashlib, algorithm.lower())()  
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b''):
            hash_object.update(chunk)
    return hash_object.hexdigest()

def compare_hashes(file1_path, file2_path, algorithm):
    hash1 = calculate_hash(file1_path, algorithm)
    hash2 = calculate_hash(file2_path, algorithm)
    if hash1 == hash2:
        print("The files have identical hashes.")
    else:
        print("The files have different hashes.")

def hash_directory(directory, algorithm):
    for root, _, files in os.walk(directory):
        for file in tqdm(files, desc=f"Hashing {root}"):
            file_path = os.path.join(root, file)
            file_hash = calculate_hash(file_path, algorithm)
            print(f"{file_path} - {algorithm}: {file_hash}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="File Hash Calculator")
    parser.add_argument("path", help="Path to the file or directory")
    parser.add_argument("-a", "--algorithm", default="MD5",
                        choices=["MD5", "SHA-256", "SHA-1"],
                        help="Hashing algorithm to use")
    parser.add_argument("-c", "--compare", help="Path to a second file for comparison")
    parser.add_argument("-r", "--recursive", action="store_true", 
                        help="Recursively hash all files in a directory")
    args = parser.parse_args()

    if args.compare:
        compare_hashes(args.path, args.compare, args.algorithm)
    elif args.recursive: 
        hash_directory(args.path, args.algorithm)
    else:
        file_hash = calculate_hash(args.path, args.algorithm)
        print(f"{args.path} - {args.algorithm}: {file_hash}")
