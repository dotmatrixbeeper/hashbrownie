use hex_literal::hex;

#[test]
fn test_single_byte() {
    let message = "a";
    let crate_hash = hashbrownie::md5(message.as_bytes());
    let target_hash = hex!("0cc175b9c0f1b6a831c399e269772661");
    println!("crate hash for \"{}\": {}", message, crate_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>());
    println!("target hash for \"{}\": {}", message, target_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>());
    
    assert_eq!(crate_hash, target_hash);
}

#[test]
fn test_hello_world() {
    let message = "hello world";
    let crate_hash = hashbrownie::md5(message.as_bytes());
    let target_hash = hex!("5eb63bbbe01eeed093cb22bb8f5acdc3");
    println!("crate hash for \"{}\": {}", message, crate_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>());
    println!("target hash for \"{}\": {}", message, target_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>());
    
    assert_eq!(crate_hash, target_hash);
}

#[test]
fn test_abc() {
    let message = "abc";
    let crate_hash = hashbrownie::md5(message.as_bytes());
    let target_hash = hex!("900150983cd24fb0d6963f7d28e17f72");
    println!("crate hash for \"{}\": {}", message, crate_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>());
    println!("target hash for \"{}\": {}", message, target_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>());
    
    assert_eq!(crate_hash, target_hash);
}

#[test]
fn test_empty() {
    let message = "";
    let crate_hash = hashbrownie::md5(message.as_bytes());
    let target_hash = hex!("d41d8cd98f00b204e9800998ecf8427e");
    println!("crate hash for \"{}\": {}", message, crate_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>());
    println!("target hash for \"{}\": {}", message, target_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>());
    
    assert_eq!(crate_hash, target_hash);
}

#[test]
fn test_all_zeros() {
    let message = [0x00u8; 64];
    let crate_hash = hashbrownie::md5(&message);
    println!("crate hash for [0x00; 64]: {}", crate_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>());
}

#[test]
fn test_all_ones() {

    let message = [0xFFu8; 64];
    let crate_hash = hashbrownie::md5(&message);
    println!("crate hash for [0xFF; 64]: {}", crate_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>());
}

#[test]
fn test_output_is_16_bytes() {
    assert_eq!(hashbrownie::md5(b"abc").len(), 16);
}

#[test]
fn test_deterministic() {
    assert_eq!(hashbrownie::md5(b"abc"), hashbrownie::md5(b"abc"));
}

#[test]
fn test_different_inputs_differ() {
    assert_ne!(hashbrownie::md5(b"abc"), hashbrownie::md5(b"cba"));
}

// 55 bytes: fits in one block (55 + 1 padding byte + 8 length = 64)
#[test]
fn test_55_bytes() {
    assert_eq!(hashbrownie::md5(&[b'a'; 55]), hex!("ef1772b6dff9a122358552954ad0df65"));
}

// 56 bytes: overflows into a second block (56 + 1 padding byte + 8 length > 64)
#[test]
fn test_56_bytes() {
    assert_eq!(hashbrownie::md5(&[b'a'; 56]), hex!("3b0c8ac703f828b04c6c197006d17218"));
}

// 57-63 bytes: all force two blocks, good to sanity check
#[test]
fn test_63_bytes() {
    assert_eq!(hashbrownie::md5(&[b'a'; 63]), hex!("b06521f39153d618550606be297466d5"));
}

// 64 bytes: exactly one full block, padding goes in a second block entirely
#[test]
fn test_64_bytes() {
    assert_eq!(hashbrownie::md5(&[b'a'; 64]), hex!("014842d480b571495a4a0363793f7367"));
}

// 128 bytes: exactly two full blocks
#[test]
fn test_128_bytes() {
    assert_eq!(hashbrownie::md5(&[b'a'; 128]), hex!("e510683b3f5ffe4093d021808bc6ff70"));
}

// All zero bytes at boundaries
#[test]
fn test_55_zero_bytes() {
    assert_eq!(hashbrownie::md5(&[0x00; 55]), hex!("c9ea3314b91c9fd4e38f9432064fd1f2"));
}

#[test]
fn test_56_zero_bytes() {
    assert_eq!(hashbrownie::md5(&[0x00; 56]), hex!("e3c4dd21a9171fd39d208efa09bf7883"));
}

// All 0xFF bytes
#[test]
fn test_55_max_bytes() {
    assert_eq!(hashbrownie::md5(&[0xFF; 55]), hex!("fd696aa639acaba9ce0e0964028fbe81"));
}

#[test]
fn test_56_max_bytes() {
    assert_eq!(hashbrownie::md5(&[0xFF; 56]), hex!("74444b7e7b01632f3277365c8ca35ec2"));
}