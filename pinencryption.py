from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
import os

class PINAES:
    def __init__(self, key):
        self.key = key
    
    # Function to encrypt plain text.
    def encrypt_text(self, pin):
        # First pad the PIN.
        # If the text isn't the correct amount of bytes, add padding
        # by slapping a few extra bits on the end. 
        padded_pin = pad(pin, AES.block_size)
        # Set an initialization vector. Purpose of the IV is to
        # produce different encrypted data so attackers can't use
        # cryptoanalysis to deduce the key or message.
        iv = Random.new().read(AES.block_size)
        # Now create a new cipher using the key and initialization
        # vector. We use CBC mode here.
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(padded_pin)

    # Use the encrypt_text function and cycle it through a file.
    # This function opens a file, reads the contents and then
    # assigns it to plain text variables to be encoded.
    # The original unencrypted files are then removed.
    def encrypt_file(self, file):
        # Must read with 'b' tag as binary to pad correctly.
        with open(file, 'rb') as f:
            exposed_text = f.read()
        encrypted_file = self.encrypt_text(exposed_text)
        # Now write the encoded PIN to a new encoded file.
        with open(file + ".enc", 'wb') as f:
            f.write(encrypted_file)
        os.remove(file)

    def decrypt_text(self, encrypted_text):
        # Set a new initialization vector. Strip it from the right
        # by the block_size - possible as we are aware of block_size.
        iv = encrypted_text[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_text = cipher.decrypt(encrypted_text[AES.block_size:])
        # Decrypted text is mostly complete, but comes with annoying trailing bytes.
        # Need to prune these by using a strip function to remov whitespace from the right
        # and remaining bytes.
        return decrypted_text.rstrip()
    
    # Revert the changes done in encrypt_file.
    # Essentially just: decrypt the text, rename the file to remove .enc extension.
    def decrypt_file(self, encrypted_file):
        with open(encrypted_file, 'rb') as f:
            encrypted_text = f.read()
        decrypted_text = self.decrypt_text(encrypted_text)
        with open(encrypted_file[:-4], 'wb') as f:
            f.write(decrypted_text)
        os.remove(encrypted_file)
    
    # Scan a secure directory for all files.
    # Of those files, decide whether they are to be encrypted or decrypted by
    # further function calls.
    # Also handle some validation here. PINs cannot be greater or less than
    # four digits and will be disregarded.
    def get_directory(self):
        secure_base_directory = os.path.dirname(os.path.realpath(__file__))
        files_list = []
        encrypted_files_list = []
        # Need to check whether we're on Windows or Linux.
        # Start by grabbing the directory name.
        if os.name == 'nt':
            secure_directory = secure_base_directory + "\secure"
        elif os.name == 'posix':
            secure_directory = secure_base_directory + "/secure"
        
        # For each file in this directory, check if files are encrypted
        # or unencrypted by inspecting file extensions. Then append to corresponding
        # list.
        for secure_directory, subdirectories, files in os.walk(secure_directory):
            if os.name == 'nt':
                for fi in os.listdir(secure_directory):
                    if fi.endswith(".txt"):
                        with open(secure_directory + "\\" + fi) as verify_fi:
                            verify_pin = verify_fi.read()
                            if len(verify_pin) == 4:
                                files_list.append(secure_directory + "\\" + fi)
                            else:
                                print("PIN is less than or greater than four digits. Disregarded.")
                    else:
                        encrypted_files_list.append(secure_directory + "\\" + fi)
            elif os.name == 'posix':
                 files_list.append(secure_directory + "/" + fi)
        return files_list, encrypted_files_list
    
    # Now that we have a list of all PINs in a secure directory,
    # encrypt or decrypt them.
    def encrypt_directory(self):
        decrypted_files, encrypted_files = self.get_directory()
        for file in decrypted_files:
            self.encrypt_file(file)
    
    def decrypt_directory(self):
        decrypted_files, encrypted_files = self.get_directory()
        for file in encrypted_files:
            self.decrypt_file(file)


if __name__== "__main__":
    # The script should always be launched from the build
    # directory. This allows the system to search for folders to be
    # encrypted without user interference.

    # Temporary key to feed to PINAES.
    key = b"1234567891234561"
    encryption = PINAES(key)

    # Firstly need a key. The stronger the key,
    # the stronger the encryption. Needs to be secured from randomness.
    # When debugging it might be good to randomly generate a key,
    # but this tool is assumed TO be production and as such needs
    # be secured as so. As such, the key is stored in an external file
    # and is locked from some users.
    # If we're in the directory with the encoded key:
    if os.path.isfile("key.txt.enc"):
        while True:
            # Ask the user for the key.
            input_key = str(input("Enter key: "))
            encryption.decrypt_file("key.txt.enc")
            
            # Now cross-reference it with the stored encrypted key.
            cross_reference_key = ""
            with open("key.txt", "r") as k:
                cross_reference_key = k.readlines()
            if cross_reference_key[0] == input_key:
                encryption.encrypt_file("key.txt")
                # Break here, as we successfully encrypt a new key.
                break
            else:
                print("Incorrect password. A new password will not be generated, you must contact an administrator.")
                # Make sure to encrypt the key back up afterwards!
                encryption.encrypt_file("key.txt")
                exit()
        
        while True:
            encrypt_or_decrypt = int(input("Enter 1 to encrypt or 2 to decrypt."))
            if encrypt_or_decrypt == 1:
                encryption.encrypt_directory()
                exit()
            elif encrypt_or_decrypt == 2:
                encryption.decrypt_directory()
                exit()
            else:
                print("Invalid option.")
    
    # If we don't have an encoded key:
    else:
        while True:
            input_key = str(input("Key does not exist. Enter a key to use for decryption: "))
            validate_key = str(input("Please verify the key: "))
            if validate_key == input_key:
                break
            else:
                print("Your passwords are not the same.")
        k = open("key.txt", "w+")
        k.write(input_key)
        k.close()
        # Now encrypt the key.
        encryption.encrypt_file("key.txt")
        print("Key set and encrypted.")
