use nom::branch::alt;
use nom::bytes::complete::*;
use nom::combinator::all_consuming;
use nom::combinator::map;
use nom::combinator::recognize;
use nom::error::ContextError;
use nom::error::ParseError;
use nom::multi::many0;
use nom::sequence::pair;
use nom::Compare;
use nom::CompareResult;
use nom::Finish;
use nom::IResult;
use nom::InputLength;
use nom::InputTake;
use nom::InputTakeAtPosition;
use nom::Offset;
use nom::Slice;
use nom_locate::LocatedSpan;
use std::ops::RangeTo;
use strum_macros::EnumString;

type Span<'a> = LocatedSpan<&'a str>;

#[derive(Clone, Copy, Debug, EnumString, PartialEq)]
pub(crate) enum TokenType {
    /// Any valid word in the zone file.
    Word,

    /// One or more whitespace characters (not including LineEndings)
    Whitespace,

    /// TODO Add numbers? Add String Literals

    /// A comment
    Comment,

    /// Line encoding
    LineEnding,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) struct Token<'a> {
    pub r#type: TokenType,
    pub pos: Span<'a>,
}

impl<'a> Token<'a> {
    /// Returns the text for this token.
    pub fn as_str(&self) -> &'a str {
        *self.pos.fragment()
    }
}

/// A special type holding a multiple Tokens. This type implements various
/// methods required for Nom.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Tokens<'a> {
    // TODO Change this to take a slice directly.
    tokens: Vec<Token<'a>>,
}

pub fn line_ending<T, E: ParseError<T>>(input: T) -> IResult<T, T, E>
where
    T: Compare<&'static str>,
    T: InputTake,
    T: Clone + Offset + Slice<RangeTo<usize>>,
{
    tag("\n")(input)
}

pub fn comment<T, E: ParseError<T>>(input: T) -> IResult<T, T, E>
where
    T: InputTakeAtPosition<Item = char>, // For take_while1
    T: Compare<&'static str>,
    T: InputTake,
    T: Clone + Offset + Slice<RangeTo<usize>>,
{
    // TODO This could be changed to take_until
    recognize(pair(tag(";"), take_while1(|c: char| c != '\n')))(input)
}

pub fn whitespace<T, E: ParseError<T>>(input: T) -> IResult<T, T, E>
where
    T: InputTakeAtPosition<Item = char>, // For take_while1
{
    take_while1(|c: char| c.is_whitespace())(input)
}

pub fn word<T, E: ParseError<T>>(input: T) -> IResult<T, T, E>
where
    T: InputTakeAtPosition<Item = char>, // For take_while1
{
    take_while1(|c: char| !c.is_whitespace())(input)
}

/// Take the input in turn into a sequence of tokens. This allows
/// us to more easily handle comments, and records split across new lines.
pub(crate) fn tokenise<'a, E: ParseError<Span<'a>> + ContextError<Span<'a>>>(
    s: nom_locate::LocatedSpan<&'a str>,
) -> Result<Tokens, E> {
    let ret = all_consuming(map(
        many0(
            // The token is one of:
            alt((
                map(line_ending, |x| Token {
                    r#type: TokenType::LineEnding,
                    pos: x,
                }),
                // Comment starting with ;
                map(comment, |x| Token {
                    r#type: TokenType::Comment,
                    pos: x,
                }),
                // Something that is whitespace
                map(whitespace, |x| Token {
                    r#type: TokenType::Whitespace,
                    pos: x,
                }),
                // Something that isn't a whitspace
                map(word, |x| Token {
                    r#type: TokenType::Word,
                    pos: x,
                }),
            )),
        ),
        |tokens| Tokens::new(&tokens),
    ))(s)
    .finish();

    match ret {
        Err(e) => Err(e),
        Ok((remaining, result)) => {
            assert!(remaining.is_empty(), "all input should have been consumed.");
            Ok(result)
        }
    }
}

impl<'a> Tokens<'_> {
    fn new(tokens: &[Token<'a>]) -> Tokens<'a> {
        Tokens {
            tokens: tokens.to_vec(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

impl std::fmt::Display for Tokens<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        for t in &self.tokens {
            writeln!(
                f,
                "{}:{} {:?} {}",
                t.pos.location_line(),
                t.pos.get_column(),
                t.r#type,
                t.pos.fragment()
            )?;
        }
        Ok(())
    }
}

impl<'a> std::ops::Index<usize> for Tokens<'a> {
    type Output = Token<'a>;

    fn index(&self, i: usize) -> &Self::Output {
        self.tokens.index(i)
    }
}

impl InputTake for Tokens<'_> {
    /// Returns a slice of `count` bytes. panics if count > length
    fn take(&self, count: usize) -> Self {
        Tokens::new(&self.tokens[0..count])
    }

    /// Split the stream at the `count` byte offset. panics if count > length
    fn take_split(&self, count: usize) -> (Self, Self) {
        let (prefix, suffix) = self.tokens.split_at(count);
        (Tokens::new(suffix), Tokens::new(prefix))
    }
}

impl Compare<TokenType> for Tokens<'_> {
    fn compare(&self, token_type: TokenType) -> nom::CompareResult {
        if self.tokens.is_empty() {
            return CompareResult::Incomplete;
        }

        // Compare the first token agaisnt the single token_type.
        if self.tokens[0].r#type == token_type {
            CompareResult::Ok
        } else {
            CompareResult::Error
        }
    }

    fn compare_no_case(&self, token: TokenType) -> CompareResult {
        // TokenTypes are not case sensitive
        self.compare(token)
    }
}

impl InputLength for TokenType {
    fn input_len(&self) -> usize {
        1 // A single TokenType is one long
    }
}

impl InputLength for Tokens<'_> {
    fn input_len(&self) -> usize {
        self.tokens.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::error::VerboseError;

    fn print_err2<I: std::fmt::Debug, O: std::fmt::Debug>(
        input: I,
        err: IResult<I, O, VerboseError<I>>,
    ) {
        // If there is a error print a nice set of debugging.
        println!("VerboseError: {:#?}", err);

        /*
        match err {
            Err(Err::Error(e)) | Err(Err::Failure(e)) => {
                println!(
                    "VerboseError - `root::<VerboseError>(data)`:\n{}",
                    convert_error(input, e)
                );
            }
            _ => {}
        }
        */
    }

    #[test]
    fn test_tokenise() {
        let input = Span::new(
            // "$ORIGIN example.com.     ; designates the start of this zone file in the namespace
            "VENERA  A       10.1.0.52",
        );
        tokenise::<VerboseError<LocatedSpan<&str>>>(input).unwrap();

        /*
        TODO
                println!("{}", tokens);

                let ret = parse_tokens::<VerboseError<Tokens>>(tokens.clone()); // TODO Avoid this clone!
                if ret.is_err() {
                    print_err2(tokens, ret);
                    panic!("failed '{}'", input)
                }

                let (remaining, got) = ret.unwrap();
                //assert_eq!(got, want);
                assert!(
                    remaining.is_empty(),
                    "all tokens should have been consumed."
                );

                panic!("blah");
        */
        /*
        let position = output.unwrap().1.position;
        assert_eq!(position.location_offset(), 14);
        assert_eq!(position.location_line(), 2);
        assert_eq!(position.fragment(), &"");
        assert_eq!(position.get_column(), 2);
        */
    }
}
