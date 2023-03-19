use openssl::error::ErrorStack;
use openssl::rsa::{Padding, Rsa};

use std::{env, io};

fn format_public_key(public_key: String) -> String {
    format!(
        "-----BEGIN PUBLIC KEY-----
{}
-----END PUBLIC KEY-----",
        public_key
    )
}

fn format_private_key(private_key: String) -> String {
    format!(
        "-----BEGIN RSA PRIVATE KEY-----
{}
-----END RSA PRIVATE KEY-----",
        private_key
    )
}

#[derive(Debug)]
struct Nft {
    token_name: String,
    encrypted_data: Vec<u8>,
}

impl Nft {
    fn new(token_name: String, public_key: String, data: String) -> Result<Nft, ErrorStack> {
        let encrypted_data = Self::encrypt_data(data, public_key)?;
        Ok(Nft {
            token_name,
            encrypted_data,
        })
    }
    fn encrypt_data(data: String, public_key: String) -> Result<Vec<u8>, ErrorStack> {
        let rsa = Rsa::public_key_from_pem(format_public_key(public_key).as_bytes())?;
        let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
        let _ = rsa.public_encrypt(data.as_bytes(), &mut buf, Padding::PKCS1)?;
        Ok(buf)
    }

    fn decrypt_data(&self, private_key: String) -> String {
        let full_private_key = format_private_key(private_key);
        let rsa = Rsa::private_key_from_pem(full_private_key.as_bytes()).unwrap();
        let mut buf: Vec<u8> = vec![0; rsa.size() as usize];
        rsa.private_decrypt(&self.encrypted_data, &mut buf, Padding::PKCS1)
            .unwrap();
        String::from_utf8(buf).unwrap()
    }
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let action = &args[1];
    match action.as_str() {
        "keys" => generate_keys(),
        "create" => create_nft(),
        _ => println!("Invalid command"),
    }
    Ok(())
}

fn create_nft() {
    let token_name = take_input("Please enter token name -").unwrap();
    let public_key = take_input("Please enter the public key -").unwrap();
    let data = take_input("Please enter url of jpeg -").unwrap();
    let created_nft = Nft::new(token_name, public_key, data).unwrap();
    println!("The Nft is {:?}", created_nft);
    let private_key = take_input("Please enter the private key -").unwrap();
    let decrypted_data = created_nft.decrypt_data(private_key);
    println!("The data is {}", decrypted_data);
}

fn take_input(prompt: &str) -> Result<String, io::Error> {
    let mut user_input = String::new();
    println!("{}", prompt);
    let stdin = io::stdin();
    stdin.read_line(&mut user_input)?;
    user_input.pop();
    Ok(user_input)
}

fn generate_keys() {
    let rsa = Rsa::generate(1024).unwrap();
    let private_key: Vec<u8> = rsa.private_key_to_pem().unwrap();
    let public_key: Vec<u8> = rsa.public_key_to_pem().unwrap();

    println!("Private key: {}", String::from_utf8(private_key).unwrap());
    println!("Public key: {}", String::from_utf8(public_key).unwrap());
}
