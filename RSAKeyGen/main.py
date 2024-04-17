from RSAKeyGenerator import generate_rsa_keys, encrypt_with_aes, save_keys

while True:
    pin = input("Enter your PIN or type 'exit' to quit: ")
    if pin.lower() == 'exit':
        print("Exiting the application.")
        break

    try:
        private_key, public_key = generate_rsa_keys()
        nonce, ciphertext, tag = encrypt_with_aes(private_key, pin)
        save_keys(public_key, ciphertext)
        print("Keys were generated and saved successfully.")
    except Exception as e:
        print(f"An error occurred while generating keys: {str(e)}")
