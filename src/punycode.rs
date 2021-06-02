// This is a punycode implementation. Current it's not used, and dead code.
//
// https://www.gnu.org/software/libidn/doxygen/punycode_8c_source.html
// https://r12a.github.io/app-conversion/
// https://github.com/algo26-matthias/idna-convert
// https://unicode.org/reports/tr46/
//
#![allow(clippy::absurd_extreme_comparisons)] // To support the const_assert below.

// Puncode parameters: https://datatracker.ietf.org/doc/html/rfc3492#section-5
const BASE: u32 = 36;
const TMIN: u32 = 1;
const TMAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: char = 0x80 as char; // The first non-ASCII code point. // TODO Should this be a char?
const DELIMITER: char = '-';

// Bootstring parameters: https://datatracker.ietf.org/doc/html/rfc3492#section-4
const_assert!(TMIN <= TMAX && TMAX < BASE);
const_assert!(SKEW >= 1);
const_assert!(DAMP >= 2);
const_assert!(INITIAL_BIAS % BASE <= BASE - TMIN);

// from_char maps the encoded code-points to their digit values.
// The returned value is in the range 0 to BASE.
fn from_char(c: char) -> u8 {
    match c {
        'A'..='Z' => c as u8 - b'A',
        'a'..='z' => c as u8 - b'a',
        '0'..='9' => c as u8 - b'0' + 26,
        _ => panic!("invalid char"), // TODO
    }
}

// to_char maps the digit-values to their lower-case unicode.
// The supplied value must be in the range 0 to BASE.
fn to_char(i: u8) -> char {
    (match i {
        0..=25 => b'a' + i,
        26..=35 => b'0' + (i-26),
        _ => panic!("invalid digit"), // TODO
    }) as char
}

// Bias adaptation
//
// num_points is the total number of code points encoded/decoded so
// far (including the one corresponding to this delta itself, and
// including the basic code points).
//
// Reference:
// * https://datatracker.ietf.org/doc/html/rfc3492#section-3.4
// * https://datatracker.ietf.org/doc/html/rfc3492#section-6.1
fn adapt(delta: u32, num_points: u32, first_time: bool) -> u32 {
    // delta is scaled in order to avoid overflow.
    let mut delta = if first_time {
        // When this is the very first delta, the divisor is not 2, but
        // instead a constant called damp.  This compensates for the fact
        // that the second delta is usually much smaller than the first.
        delta / DAMP
    } else {
        delta / 2
    };

    // Delta is increased to compensate for the fact that the next delta
    // will be inserting into a longer string.
    delta = delta + (delta / num_points);

    let mut k = 0;
    while delta > ((BASE - TMIN) * TMAX) / 2 {
        delta /= BASE - TMIN;
        k += BASE;
    }

    k + (((BASE - TMIN + 1) * delta) / (delta + SKEW))
}

// Encodes a string into punycode.
pub fn encode(input: &str) -> Result<String, ()> {
    let mut output = String::new();
    let mut unicode = Vec::<char>::new();  // Non-basic code points (the ones we need to encode).
    for c in input.chars() {
        if c.is_ascii() {
            // All basic code points appearing in the extended string are
            // represented literally at the beginning of the basic string, in their
            // original order, followed by a delimiter if (and only if) the number
            // of basic code points is nonzero.
            output.push(c);
        } else {
            unicode.push(c); // Perhaps store the index to make below faster
        }
    }

    let basic_len = output.len() as u32;

    if !output.is_empty() {
        output.push(DELIMITER);
    }

    if unicode.is_empty() {
        return Ok(output);
    }


    // "Insertion unsort coding" encodes the non-basic code points as deltas,
    // and processes the code points in numerical order rather than in order
    // of appearance, which typically results in smaller deltas.
    unicode.sort_by(|a, b| b.cmp(&a));
    unicode.dedup();

    if *unicode.last().unwrap() < INITIAL_N {
        // If the input contains a non-basic code point < n then fail
        panic!("the input contains a non-basic code point < n");
    }

    let mut last_char = INITIAL_N as u32;       // The first non-ASCII code point.
    let mut bias = INITIAL_BIAS;
    let mut delta = 0;
    let mut h = basic_len;

    //while h < input.len() {
    while let Some(c) = unicode.pop() {
        // The minimum {non-basic} code point >= n in the input
        let cur_char = c as u32;

        // println!("next code point to insert is {:X}", m as u32);

        // The deltas are represented as "generalized variable-length integers",
        // which use basic code points to represent nonnegative integers.
        delta += (cur_char - last_char) * (h + 1); // TODO fail on overflow

        // TODO We can remove this `c in input` loop, all it does is move the delta along.
        for c in input.chars() {
            let c = c as u32;
            if c < cur_char {
                delta += 1; // TODO Fail on overflow
            }

            // We found the current unicode character, so lets encode it.
            if c == cur_char {
                // print!("needed delta is {}, encodes as ", delta);

                let mut q = delta;
                let mut k = BASE;
                loop {
                    assert!(!(bias < k && k < (bias + TMIN)));
                    let t = if k <= bias {
                        TMIN
                    } else if k >= bias + TMAX {
                        TMAX
                    } else {
                        k - bias
                    };

                    if q < t {
                        break;
                    }

                    // TODO Check that this value will always fit into a u8.
                    // output the code point for digit t + ((q - t) mod (base - t))
                    let output_c = to_char((t + ((q - t) % (BASE - t))) as u8);
                    output.push(output_c);
                    // print!("{}", output_c);

                    q = (q - t) / (BASE - t);
                    k += BASE;
                }

                // print!("{}", to_char(q as u8));

                // Output the last digit for cur_char.
                output.push(to_char(q as u8));

                bias = adapt(delta, h + 1, h == basic_len);

                // println!();
                // println!("bias becomes {}", bias);

                delta = 0;
                h += 1;
            }
        }
        
        delta += 1;
        last_char = cur_char + 1;
    }

    // println!("output is \"{}\"", output);

    Ok(output)
}

// A set of test cases.
// Shout out to https://r12a.github.io/app-conversion/ which helped validate some of the unicode.
#[cfg(test)]
static TESTS: [(&str, &str, &str); 47] = [
    // From rfc3492, various examples of "Why can't they just speak in <language>?"
    ("ليهمابتكلموشعربي؟", "egbpdaj6bu4bxfgehfvwxn", "Arabic (Egyptian)"),
    ("他们为什么不说中文", "ihqwcrb4cv8a8dqg056pqjye", "Chinese (simplified)"),
    ("他們爲什麽不說中文", "ihqwctvzc91f659drss3x8bo0yb", "Chinese (traditional)"),
    ("Pročprostěnemluvíčesky", "Proprostnemluvesky-uyb24dma41a", "Czech"),
    ("למההםפשוטלאמדבריםעברית", "4dbcagdahymbxekheh6e0a7fei0b", "Hebrew"),
    ("यहलोगहिन्दीक्योंनहींबोलसकतेहैं", "i1baa7eci9glrd9b2ae1bj0hfcgg6iyaf8o0a1dig0cd", "Hindi (Devanagari)"),
    ("なぜみんな日本語を話してくれないのか", "n8jok5ay5dzabd5bym9f0cm5685rrjetr6pdxa", "Japanese (kanji and hiragana)"),
    ("세계의모든사람들이한국어를이해한다면얼마나좋을까", "989aomsvi5e83db1d2a355cv1e0vak1dwrv93d5xbh15a0dt30a5jpsd879ccm6fea98c", "Korean (Hangul syllables)"),
    ("почемужеонинеговорятпорусски", "b1abfaaepdrnnbgefbadotcwatmq2g4l", "Russian (Cyrillic)"),
    ("PorquénopuedensimplementehablarenEspañol", "PorqunopuedensimplementehablarenEspaol-fmd56a", "Spanish"),
    ("TạisaohọkhôngthểchỉnóitiếngViệt", "TisaohkhngthchnitingVit-kjcr8268qyxafd2f1b9g", "Vietnamese"),

    // Japanese music artists, song titles, and TV programs, from rfc3492.
    ("3年B組金八先生", "3B-ww4c5e180e575a65lsy2b", "3<nen>B<gumi><kinpachi><sensei>"),
    ("安室奈美恵-with-SUPER-MONKEYS", "-with-SUPER-MONKEYS-pc58ag80a8qai00g7n9n", "<amuro><namie>-with-SUPER-MONKEYS"),
    ("Hello-Another-Way-それぞれの場所", "Hello-Another-Way--fc4qua05auwb3674vfr0b", "Hello-Another-Way-<sorezore><no><basho>"),
    ("ひとつ屋根の下2", "2-u9tlzr9756bt3uc0v", "<hitotsu><yane><no><shita>2"),
    ("MajiでKoiする5秒前", "MajiKoi5-783gue6qz075azm5e", "Maji<de>Koi<suru>5<byou><mae>"),
    ("パフィーdeルンバ", "de-jg4avhby1noc0d", "<pafii>de<runba>"),
    ("そのスピードで", "d9juau41awczczp", "<sono><supiido><de>"),

    // From https://en.wikipedia.org/wiki/Punycode#Examples
    ("bücher", "bcher-kva", "Simple wikipedia example."),
    ("", "", "The empty string."),
    ("a", "a-", "Only ASCII characters, one, lowercase."),
    ("A", "A-", "Only ASCII characters, one, uppercase."),
    ("3", "3-", "Only ASCII characters, one, a digit."),
    ("-", "--", "Only ASCII characters, one, a hyphen."),
    ("--", "---", "Only ASCII characters, two hyphens."),
    ("London", "London-", "Only ASCII characters, more than one, no hyphens."),
    ("Lloyd-Atkinson", "Lloyd-Atkinson-", "Only ASCII characters, one hyphen."),
    ("This has spaces", "This has spaces-", "Only ASCII characters, with spaces."),
    ("-> $1.00 <-", "-> $1.00 <--", "Only ASCII characters, mixed symbols."),
    ("ü", "tda", "No ASCII characters, one Latin-1 Supplement character."),
    ("α", "mxa", "No ASCII characters, one Greek character."),
    ("例", "fsq", "No ASCII characters, one CJK character."),
    ("😉", "n28h", "No ASCII characters, one emoji character."),
    ("αβγ", "mxacd", "No ASCII characters, more than one character."),
    ("München", "Mnchen-3ya", "Mixed string, with one character that is not an ASCII character."),
    ("Mnchen-3ya", "Mnchen-3ya-", "Double-encoded Punycode of \"München\"."),
    ("München-Ost", "Mnchen-Ost-9db", "Mixed string, with one character that is not ASCII, and a hyphen."),
    ("Bahnhof München-Ost", "Bahnhof Mnchen-Ost-u6b", "Mixed string, with one space, one hyphen, and one character that is not ASCII."),
    ("abæcdöef", "abcdef-qua4k", "Mixed string, two non-ASCII characters."),
    ("правда", "80aafi6cg", "Russian, without ASCII."),
    ("ยจฆฟคฏข", "22cdfh1b8fsa", "Thai, without ASCII."),
    ("도메인", "hq1bm8jm9l", "Korean, without ASCII."),
    ("ドメイン名例", "eckwd4c7cu47r2wf", "Japanese, without ASCII."),
    ("MajiでKoiする5秒前", "MajiKoi5-783gue6qz075azm5e", "Japanese with ASCII."),
    ("「bücher」", "bcher-kva8445foa", "Mixed non-ASCII scripts (Latin-1 Supplement and CJK)."),

    // Others edge cases
    ("☺", "74h", "Smiling Face."),
    ("i❤", "i-7iq", "i❤️.ws"),
    // ("☺️", "74h", "Smiling Face followed by a variation Selector-16 (U+FE0F)."),
    // ("i❤️", "i-7iq", "i❤️.ws with a variation Selector-16 (U+FE0F)"),
];

#[test]
pub fn test_encode() {
    for test in TESTS {
        assert_eq!(encode(test.0).unwrap(), test.1);
    }
}
