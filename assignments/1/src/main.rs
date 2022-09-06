use std::fs;

use clap::Parser;
use itertools::Itertools;
use text_io::scan;

#[derive(Parser)]
struct Cli {
    #[clap(parse(from_os_str))]
    ipath: std::path::PathBuf,
}

// Find the vector consisting of the unique chars in s,
// ordered from most to least # of occurances
fn char_order(s: &str) -> Vec<char> {
    s.chars()
        .counts()
        .into_iter()
        .sorted_by(|a, b| usize::cmp(&b.1, &a.1))
        .map(|(chr, _cnt)| chr)
        .collect()
}

// Get index of first occurance of 'el' in vec
fn index_of<T: Eq>(el: T, vec: &[T]) -> usize {
    vec.iter().position(|x| *x == el).unwrap()
}

// Convert in_str from using input alphabet to output alphabet.
// Panics if input & output alphabets are differently sized
fn convert_alphabet(in_alph: &[char], out_alph: &[char], in_str: &str) -> String {
    assert_eq!(in_alph.len(), out_alph.len());
    in_str
        .chars()
        .map(|c| out_alph[index_of(c, &in_alph)])
        .collect()
}

fn main() {
    // Reference english letter frequencies
    //let ref_ord = "EATOINSHRDLUCMWFGYPBVKJXQZ";
    let ref_ord = [
        'E', 'A', 'T', 'O', 'I', 'N', 'S', 'H', 'R', 'D', 'L', 'U', 'C', 'M', 'W', 'F', 'G', 'Y',
        'P', 'B', 'V', 'K', 'J', 'X', 'Q', 'Z',
    ];
    // Read UTF-8 input from file passed as command line arg
    let args = Cli::parse();
    let ciphertext = fs::read_to_string(args.ipath).expect("Failed to read input!");

    // Order of chars in ciphertext should be encrypted version of ref_ord
    let mut probable_key = char_order(&ciphertext);

    println!(
        "English letter order is {0}\nLetter order (key) for ciphertext is {1}",
        ref_ord.iter().collect::<String>(),
        probable_key.iter().collect::<String>()
    );

    // Loop until user is happy with key
    loop {
        // Decrypt first 100 characters of cipher text, ask if alphabet OK or to input new, then decrypt full ciphertext and put in output
        println!(
            "First 100 characters of ciphertext, then after decrypting with previous key are \n{}\n{}",
            &ciphertext[0..100],
            convert_alphabet(&probable_key, &ref_ord, &ciphertext[0..100])
        );
        println!("Would you like to decrypt everything with this key?\nIf so, please enter 'y'\nOtherwise, enter a key to use instead (Only ASCII Uppercase will work how you expect!)");
        let input: String;
        println!(
            "plaintext key  {}\nciphertext key {}",
            ref_ord.iter().collect::<String>(),
            probable_key.iter().collect::<String>()
        );
        scan!("{}", input);

        match input.len() {
            1 => {
                if input == "y" {
                    break;
                }
            }
            26 => { /* OK length for key */ }
            _ => {
                println!("{} is not an acceptable key length!", input.len());
                continue;
            }
        }
        probable_key = input.chars().collect();
    }

    // Decrypt & write to file
    fs::write(
        "decrypted",
        convert_alphabet(&probable_key, &ref_ord, &ciphertext),
    )
    .unwrap();
}
