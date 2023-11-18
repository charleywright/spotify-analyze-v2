use std::{
    io,
    io::{Error, ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
};

fn handle_client(mut downstream: TcpStream) -> std::io::Result<()> {
    // Check magic
    let mut starting_magic_bytes = [0; 2];
    downstream.read_exact(&mut starting_magic_bytes)?;
    if starting_magic_bytes != [0x0, 0x4] {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid magic bytes"));
    }

    // Connect to real AP
    let mut upstream = TcpStream::connect("ap.spotify.com:4070").expect("Failed to connect to Spotify AP");

    // Read ClientHello from downstream
    let mut client_hello_length_bytes = [0; 4];
    downstream.read_exact(&mut client_hello_length_bytes)?;
    let client_hello_length = u32::from_be_bytes(client_hello_length_bytes);
    println!("ClientHello protobuf size: {}", client_hello_length - 6);
    let mut client_hello_bytes: Vec<u8> = vec![0; client_hello_length as usize - 6];
    downstream.read_exact(&mut client_hello_bytes[..])?;
    println!("ClientHello: {}", hex::encode(client_hello_bytes.clone()));

    // Write ClientHello to upstream
    upstream.write_all(&starting_magic_bytes).expect("Failed to write magic bytes");
    upstream.write_all(&client_hello_length_bytes).expect("Failed to write ClientHello length");
    upstream.write_all(&client_hello_bytes[..]).expect("Failed to write ClientHello");

    // Read APResponseMessage from upstream
    let mut ap_response_length_bytes = [0; 4];
    upstream.read_exact(&mut ap_response_length_bytes)?;
    let ap_response_length = u32::from_be_bytes(ap_response_length_bytes);
    println!("APResponseMessage protobuf size: {}", ap_response_length);
    let mut ap_response_bytes: Vec<u8> = vec![0; ap_response_length as usize - 4];
    upstream.read_exact(&mut ap_response_bytes[..])?;
    println!("APResponseMessage: {}", hex::encode(ap_response_bytes.clone()));

    // Write APResponseMessage to downstream
    downstream.write_all(&ap_response_length_bytes).expect("Failed to write APResponseMessage length");
    downstream.write_all(&ap_response_bytes[..]).expect("Failed to write APResponseMessage");

    // Read ClientResponsePlaintext from downstream
    let mut client_response_plaintext_length_bytes = [0; 4];
    downstream.read_exact(&mut client_response_plaintext_length_bytes)?;
    let client_response_plaintext_length = u32::from_be_bytes(client_response_plaintext_length_bytes);
    println!("ClientResponsePlaintext protobuf size: {}", client_response_plaintext_length);
    let mut client_response_plaintext: Vec<u8> = vec![0; client_response_plaintext_length as usize - 4];
    downstream.read_exact(&mut client_response_plaintext[..])?;
    println!("ClientResponsePlaintext: {}", hex::encode(client_response_plaintext.clone()));

    // Write ClientResponsePlaintext to upstream
    upstream
        .write_all(&client_response_plaintext_length_bytes)
        .expect("Failed to write ClientResponsePlaintext length");
    upstream.write_all(&client_response_plaintext[..]).expect("Failed to write ClientResponsePlaintext");

    Ok(())
}

fn main() -> io::Result<()> {
    let host = "192.168.1.120:4070";
    let listener = TcpListener::bind(host).unwrap_or_else(|_| panic!("Failed to bind to {}", host));
    println!("Listening on {}", host);

    for stream in listener.incoming() {
        let _ = handle_client(stream?);
    }

    Ok(())
}
