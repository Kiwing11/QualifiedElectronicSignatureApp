from RSAKeyGenerator import generate_rsa_keys, encrypt_with_aes, save_keys

while True:
    pin = input("Enter your PIN or type 'exit' to quit: ")
    if pin.lower() == 'exit':
        print("Exiting the application.")
        break

    try:
        private_key, public_key = generate_rsa_keys()
        iv, ciphertext = encrypt_with_aes(private_key, pin)
        private_key = iv + ciphertext
        save_keys(private_key, public_key)
        print("Keys were generated and saved successfully.")
    except Exception as e:
        print(f"An error occurred while generating keys: {str(e)}")
