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

    /// Left / Open Parenthesis
    LeftParen,

    /// Right / Close Parenthesis
    RightParen,

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

pub fn comment<T, E: ParseError<T>>(input: T) -> IResult<T, T, E>
where
    T: InputTakeAtPosition<Item = char>, // For take_while1
    T: Compare<&'static str>,
    T: InputTake,
    T: Clone + Offset + Slice<RangeTo<usize>>,
{
    // Always parses until the end of the line (or input).
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
    take_while1(|c: char| !c.is_whitespace() && c != '(' && c != ')' && c != '"')(input)
}

/// Take the input in turn into a sequence of tokens. This allows
/// us to more easily handle comments, and records split across new lines.
pub(crate) fn tokenise<'a, E: ParseError<Span<'a>> + ContextError<Span<'a>>>(
    s: LocatedSpan<&'a str>,
) -> Result<Tokens, E> {
    let ret = all_consuming(map(
        many0(
            // The token is one of:
            alt((
                map(tag("\n"), |x| Token {
                    r#type: TokenType::LineEnding,
                    pos: x,
                }),
                map(tag("("), |x| Token {
                    r#type: TokenType::LeftParen,
                    pos: x,
                }),
                map(tag(")"), |x| Token {
                    r#type: TokenType::RightParen,
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
    use pretty_assertions::assert_eq;
    use std::ops::{RangeFrom, RangeTo};

    impl Token<'_> {
        fn new(r#type: TokenType, pos: Span) -> Token {
            Token { r#type, pos }
        }
    }

    /// Simple type that takes a LocatedSpan, and makes it easy to break up
    /// into its sub-spans.
    struct EasySpan<T, X> {
        input: LocatedSpan<T, X>,
    }

    impl<T, X> EasySpan<T, X>
    where
        LocatedSpan<T, X>: Slice<RangeFrom<usize>> + Slice<RangeTo<usize>>,
    {
        fn next(&mut self, count: usize) -> LocatedSpan<T, X> {
            let (after, before) = self.input.take_split(count);
            self.input = after;
            before
        }
    }

    #[test]
    fn test_tokenise() {
        let input = Span::new("VENERA  A      10.1.0.52 ; some comment");

        let mut span = EasySpan { input };
        let want = Tokens::new(&[
            Token::new(TokenType::Word, span.next(6)),
            Token::new(TokenType::Whitespace, span.next(2)),
            Token::new(TokenType::Word, span.next(1)),
            Token::new(TokenType::Whitespace, span.next(6)),
            Token::new(TokenType::Word, span.next(9)),
            Token::new(TokenType::Whitespace, span.next(1)),
            Token::new(TokenType::Comment, span.next(14)),
        ]);
        let got = tokenise::<VerboseError<LocatedSpan<&str>>>(input).expect("token parsing failed");
        assert_eq!(got, want);
    }

    #[test]
    fn test_tokenise_multi() {
        let input = Span::new(concat!(
            "@  IN  Action\\.domains (1\n",
            "20      ; SERIAL\n",
            "3600000); MINIMUM",
        ));

        let mut span = EasySpan { input };
        let want = Tokens::new(&[
            Token::new(TokenType::Word, span.next(1)),
            Token::new(TokenType::Whitespace, span.next(2)),
            Token::new(TokenType::Word, span.next(2)),
            Token::new(TokenType::Whitespace, span.next(2)),
            Token::new(TokenType::Word, span.next(15)),
            Token::new(TokenType::Whitespace, span.next(1)),
            Token::new(TokenType::LeftParen, span.next(1)),
            Token::new(TokenType::Word, span.next(1)),
            Token::new(TokenType::LineEnding, span.next(1)),
            Token::new(TokenType::Word, span.next(2)),
            Token::new(TokenType::Whitespace, span.next(6)),
            Token::new(TokenType::Comment, span.next(8)),
            Token::new(TokenType::LineEnding, span.next(1)),
            Token::new(TokenType::Word, span.next(7)),
            Token::new(TokenType::RightParen, span.next(1)),
            Token::new(TokenType::Comment, span.next(9)),
        ]);
        let got = tokenise::<VerboseError<LocatedSpan<&str>>>(input).expect("token parsing failed");
        assert_eq!(got, want);
    }
}
