//! The default password screen: refuses passwords that are common, structural, or trivially
//! decorated versions of either — offline, with no network call.
//!
//! NIST SP 800-63B §3.1.1.2 states that a verifier **SHALL** compare a prospective secret
//! against a blocklist of commonly used, expected, or compromised values, and ASVS v5 §6.2.4
//! asks for it at Level 1 — the baseline every application needs. The default used to be
//! [`AllowAllBreachChecker`](super::breach::AllowAllBreachChecker), which approved everything:
//! a deployment on defaults accepted `password1` and `12345678`, and the brute-force machinery
//! never fired, because a spraying campaign that tries one password across ten thousand
//! accounts never crosses any single account's threshold.
//!
//! Being offline is what lets this be a default where the HIBP checker could not: a library
//! should not start talking to a third party because it was upgraded, but it can perfectly well
//! start refusing `password`. `nest-auth` ships the identical screen.

use std::collections::HashSet;

use async_trait::async_trait;

use super::breach::PasswordBreachChecker;

/// Base words behind the overwhelming majority of real-world weak passwords.
///
/// Deliberately short. It is not a top-3000 dump and does not try to be: [`reduce_to_base_word`]
/// strips the decorations people actually add — case, leet substitutions, trailing digits and
/// punctuation — so one entry here covers `Password1`, `p@ssw0rd`, `PASSWORD123!` and the rest
/// of a family that a raw list would have to spell out one member at a time. A few hundred
/// bases is where the published top-N lists mostly *come from*; enumerating their mutations is
/// what makes those lists long, not what makes them effective.
///
/// Entries are stored already reduced, because that is the form they are compared in.
const COMMON_BASE_WORDS: &[&str] = &[
    // The perennial top of every published list.
    "password",
    "passwort",
    "passwd",
    "senha",
    "contrasena",
    "motdepasse",
    "welcome",
    "letmein",
    "changeme",
    "secret",
    "default",
    "temporary",
    "temppassword",
    "admin",
    "administrator",
    "root",
    "toor",
    "guest",
    "test",
    "testing",
    "demo",
    "sample",
    "login",
    "user",
    "username",
    "account",
    "access",
    "private",
    "security",
    "secure",
    // Keyboard rows and walks, in the shapes people type them.
    "qwerty",
    "qwertyui",
    "qwertyuiop",
    "azerty",
    "qwertz",
    "asdfgh",
    "asdfghjk",
    "asdfghjkl",
    "zxcvbn",
    "zxcvbnm",
    "qazwsx",
    "qazwsxedc",
    "wsxedc",
    "qweasd",
    "qweasdzxc",
    "poiuytrewq",
    // Affection, the second-largest family after keyboards.
    "iloveyou",
    "ilovegod",
    "loveyou",
    "lovely",
    "sweetheart",
    "darling",
    "princess",
    "prince",
    "sunshine",
    "baby",
    "angel",
    "honey",
    "butterfly",
    "flower",
    "kisses",
    // Sport, entertainment, and the fandom perennials.
    "football",
    "baseball",
    "basketball",
    "softball",
    "soccer",
    "hockey",
    "liverpool",
    "arsenal",
    "chelsea",
    "barcelona",
    "realmadrid",
    "juventus",
    "manutd",
    "manchester",
    "superman",
    "batman",
    "spiderman",
    "starwars",
    "pokemon",
    "minecraft",
    "fortnite",
    "thomas",
    "harley",
    "ferrari",
    "porsche",
    "mercedes",
    "corvette",
    "mustang",
    // Names that top every leak, and the words that keep them company.
    "michael",
    "jennifer",
    "jessica",
    "ashley",
    "daniel",
    "charlie",
    "matthew",
    "joshua",
    "andrew",
    "robert",
    "william",
    "nicole",
    "hunter",
    "jordan",
    "taylor",
    "george",
    "maggie",
    "buster",
    "shadow",
    "ginger",
    "tigger",
    "pepper",
    "cookie",
    "peanut",
    "snoopy",
    // Words people reach for when told "make it strong".
    "dragon",
    "monkey",
    "master",
    "freedom",
    "whatever",
    "trustno",
    "nothing",
    "anything",
    "computer",
    "internet",
    "samsung",
    "google",
    "facebook",
    "apple",
    "microsoft",
    "windows",
    "letmeinnow",
    "iamgod",
    "ihateyou",
    "fuckyou",
    "fuckoff",
    "bullshit",
    "asshole",
    "summer",
    "winter",
    "spring",
    "autumn",
    "january",
    "february",
    "october",
    "november",
    "december",
    "september",
    "monday",
    "friday",
    "sunday",
    "money",
    "business",
    "company",
    "office",
    "manager",
    "director",
    "service",
    "support",
    "chocolate",
    "cheese",
    "orange",
    "purple",
    "yellow",
    "silver",
    "golden",
    "diamond",
    "phoenix",
    "thunder",
    "lightning",
    "warrior",
    "ranger",
    "killer",
    "legend",
    "forever",
    "together",
    "nevermind",
    "whatsup",
    "blessed",
    "jesus",
    "jesuschrist",
];

/// Sequences a password may not consist of, in either direction.
///
/// A run long enough to fill the minimum length is not a password no matter which characters it
/// is made of, and no word list can enumerate every window of every sequence.
const SEQUENCE_ALPHABETS: &[&str] = &[
    "abcdefghijklmnopqrstuvwxyz",
    "01234567890",
    "qwertyuiopasdfghjklzxcvbnm",
];

/// The shortest reduced base that is treated as a word rather than a fragment.
///
/// Below this every string is a substring of some alphabet, which would make the sequence check
/// meaningless rather than selective — and a password whose entire word content is under four
/// characters (`a1234567`, `abc12345`) is padding around a fragment, which no list can catch
/// because there is no entry to write.
const MIN_BASE_LENGTH: usize = 4;

/// Map a leet character back to the letter it stands in for.
fn undo_leet(c: char) -> char {
    match c {
        '0' => 'o',
        '1' => 'i',
        '3' => 'e',
        '4' => 'a',
        '5' => 's',
        '7' => 't',
        '8' => 'b',
        '9' => 'g',
        '@' => 'a',
        '$' => 's',
        '!' | '|' => 'i',
        '+' => 't',
        other => other,
    }
}

/// Reduce a password to the base word its author started from.
///
/// Lowercases, strips the trailing digits and punctuation people append to satisfy a complexity
/// rule, maps leet substitutions back to letters, and drops what is left that is not
/// alphanumeric. `P@ssw0rd!`, `Password123`, and `password` all reduce to `password`, which is
/// why a few hundred bases stand in for a list many times longer.
///
/// The order matters: decoration comes off **first**, while the digits are still digits.
/// Mapping leet before that would turn the trailing `1` of `Password1` into an `i` and leave
/// `passwordi`, which matches nothing — the difference between the mechanism working and the
/// list quietly covering only its literal entries.
#[must_use]
pub fn reduce_to_base_word(password: &str) -> String {
    let lowered = password.to_lowercase();
    let undecorated = lowered.trim_end_matches(|c: char| !c.is_alphabetic());
    undecorated
        .chars()
        .map(undo_leet)
        // Letters and numbers in ANY script, not just ASCII. `is_ascii_alphanumeric` discarded
        // every non-Latin character, so a password written in Cyrillic, Han, Kana, Hangul,
        // Greek, Arabic, Hebrew or Thai reduced to the empty string — and an empty base is
        // below `MIN_BASE_LENGTH`, which `is_breached` reads as "breached". Users of those
        // scripts were refused on register, reset and change, and told their strong password
        // was commonly used, which pushes them toward the strictly smaller ASCII keyspace.
        //
        // Keeping the characters also makes a consumer's non-Latin blocklist entry reachable:
        // extra entries are normalized through this same function, so under the ASCII filter
        // every one of them collapsed to "" and could never match.
        .filter(|c| c.is_alphanumeric())
        .collect()
}

/// Whether a string is a run along one of [`SEQUENCE_ALPHABETS`], forwards or backwards.
fn is_sequential(value: &str) -> bool {
    SEQUENCE_ALPHABETS.iter().any(|alphabet| {
        let reversed: String = alphabet.chars().rev().collect();
        alphabet.contains(value) || reversed.contains(value)
    })
}

/// Whether the value is one short unit repeated to reach the length floor (`abcabcabc`).
/// Bounded to units of 1–4 so this stays a check on padding, not on any repetition.
fn is_padded_repeat(value: &str) -> bool {
    let chars: Vec<char> = value.chars().collect();
    (1..=4).any(|unit| {
        chars.len() > unit * 2
            && chars.len().is_multiple_of(unit)
            && chars.chunks(unit).all(|chunk| chunk == &chars[..unit])
    })
}

/// The default password screen. See the module docs for what it is and is not.
///
/// **A floor, not a corpus.** It refuses the base words behind the bulk of real-world weak
/// passwords, keyboard walks, single-character repeats, sequential runs, fragments padded out
/// with decoration, and any decorated form of those — but it is not the full top-3000, and it
/// knows nothing about breach corpora. A deployment that wants that extends it with
/// [`CommonPasswordChecker::with_extra_words`] (the context-specific words ASVS v5 §6.2.11 asks
/// for) or supplies the HIBP checker, which searches a real corpus over the network.
///
/// **The shipped base words are ASCII.** The reduction preserves letters and numbers in any
/// script — a strong Cyrillic, Han, Kana, Hangul, Greek, Arabic, Hebrew or Thai passphrase is
/// admitted, and used to be refused outright with the "commonly used" error, which pushed those
/// users onto the smaller ASCII keyspace. But the list itself holds no entries in those
/// scripts, so the equivalent of `password` in one of them passes this screen. A deployment
/// serving those users should add the common ones for its locale through
/// [`CommonPasswordChecker::with_extra_words`]; extras are normalized through the same
/// reduction, so a non-Latin entry matches a decorated form of itself the way an ASCII one
/// does. Held in step with nest-auth's `CommonPasswordChecker`.
pub struct CommonPasswordChecker {
    blocked: HashSet<String>,
}

impl Default for CommonPasswordChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl CommonPasswordChecker {
    /// The shipped screen, with no deployment-specific words.
    #[must_use]
    pub fn new() -> Self {
        Self {
            blocked: COMMON_BASE_WORDS.iter().map(|w| (*w).to_owned()).collect(),
        }
    }

    /// The shipped screen plus the deployment's own context words — its product, company and
    /// domain names, which are exactly the words its users reach for and which no general
    /// corpus contains (ASVS v5 §6.2.11).
    ///
    /// Entries are reduced the same way a candidate is, so listing `Acme` also refuses
    /// `Acme2024!` and `@cme123` without anyone having to think of them.
    #[must_use]
    pub fn with_extra_words<I, S>(extra: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut checker = Self::new();
        checker.blocked.extend(
            extra
                .into_iter()
                .map(|word| reduce_to_base_word(word.as_ref())),
        );
        checker
    }
}

#[async_trait]
impl PasswordBreachChecker for CommonPasswordChecker {
    async fn is_breached(&self, password: &str) -> bool {
        let base = reduce_to_base_word(password);

        // Almost nothing survived the reduction, so the password was decoration wrapped around
        // a fragment: `!!!!!!!!` and `12345678` leave nothing at all, `a1234567` leaves `a`.
        // Counted in CHARACTERS, not bytes: `len()` is the UTF-8 byte count, so a two-character
        // Han base would score 6 and clear a floor meant to be about how many characters the
        // reduction actually kept. nest-auth counts code points for the same reason.
        if base.chars().count() < MIN_BASE_LENGTH {
            return true;
        }

        if self.blocked.contains(&base) {
            return true;
        }

        // A single character repeated, before or after reduction.
        let mut chars = base.chars();
        if let Some(first) = chars.next()
            && chars.all(|c| c == first)
        {
            return true;
        }

        is_sequential(&base) || is_padded_repeat(&base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reduction is the whole mechanism: one base entry has to stand in for the family of
    /// decorated forms a raw list would need to spell out one at a time.
    #[test]
    fn the_reduction_collapses_every_decorated_form_onto_one_base() {
        for input in [
            "password",
            "Password",
            "PASSWORD",
            "Password1",
            "password123",
            "P@ssw0rd",
            "p@$$w0rd!",
            "Password2024!",
            "pa55word",
        ] {
            assert_eq!(reduce_to_base_word(input), "password", "for {input}");
        }
    }

    /// Every leet substitution is exercised, because an unmapped one is a silent hole: the
    /// candidate simply fails to match its base and sails through.
    #[test]
    fn every_leet_substitution_maps_back() {
        assert_eq!(reduce_to_base_word("p455w0rd"), "password");
        assert_eq!(reduce_to_base_word("7hunder"), "thunder");
        assert_eq!(reduce_to_base_word("8u5ter"), "buster");
        assert_eq!(reduce_to_base_word("9inger"), "ginger");
        assert_eq!(reduce_to_base_word("+3s+ing"), "testing");
        assert_eq!(reduce_to_base_word("m|chael"), "michael");
        assert_eq!(reduce_to_base_word("$hadow"), "shadow");
    }

    /// Only TRAILING decoration comes off. A leading digit is part of the word, so `1password`
    /// must not collapse onto `password` — over-blocking is its own failure.
    #[test]
    fn a_leading_digit_is_not_decoration() {
        assert_ne!(reduce_to_base_word("1password"), "password");
    }

    #[tokio::test]
    async fn it_refuses_the_entries_every_published_list_opens_with() {
        let checker = CommonPasswordChecker::new();
        for password in [
            "password",
            "Password1",
            "P@ssw0rd",
            "password123",
            "qwertyui",
            "qwerty123",
            "iloveyou",
            "sunshine",
            "football",
            "superman",
            "michael1",
            "letmein123",
            "welcome1",
            "changeme",
            "administrator",
            "trustno1",
        ] {
            assert!(checker.is_breached(password).await, "allowed {password}");
        }
    }

    /// Structural weakness no word list can enumerate: a run, a repeat, or a fragment padded
    /// out to reach the length floor.
    #[tokio::test]
    async fn it_refuses_structural_weakness() {
        let checker = CommonPasswordChecker::new();
        for password in [
            "12345678",
            "87654321",
            "abcdefgh",
            "aaaaaaaa",
            "abcabcabc",
            "1212121212",
            "!!!!!!!!",
            "a1234567",
            "abc12345",
        ] {
            assert!(checker.is_breached(password).await, "allowed {password}");
        }
    }

    /// The screen must not become a general complexity rule. A password with no relation to the
    /// bases and no structural pattern passes, whatever it looks like.
    #[tokio::test]
    async fn it_allows_a_password_that_is_merely_unusual() {
        let checker = CommonPasswordChecker::new();
        for password in [
            "correct-horse-battery-staple",
            "Tr0ub4dor&3xyz",
            "gliding-walnut-forecast",
            "9fK2mQwZ",
            "1password",
        ] {
            assert!(!checker.is_breached(password).await, "refused {password}");
        }
    }

    /// ASVS v5 §6.2.11: the deployment's own words, and their decorated forms for free.
    #[tokio::test]
    async fn it_refuses_a_deployment_context_word_and_its_decorations() {
        let checker = CommonPasswordChecker::with_extra_words(["Acme"]);

        assert!(checker.is_breached("acme").await);
        assert!(checker.is_breached("Acme2024!").await);
        assert!(checker.is_breached("@cme123").await);
        // …and the word is not in the shipped screen for everyone else.
        assert!(!CommonPasswordChecker::new().is_breached("acmecorp").await);
        // …while the shipped bases still apply.
        assert!(checker.is_breached("Password1").await);
    }

    /// `Default` is the same screen as `new`, since the builder may construct it either way.
    #[tokio::test]
    async fn default_is_the_shipped_screen() {
        assert!(
            CommonPasswordChecker::default()
                .is_breached("password")
                .await
        );
    }

    // -----------------------------------------------------------------------
    // Non-ASCII scripts
    // -----------------------------------------------------------------------

    /// A strong passphrase in a script that is not Latin must be ADMITTED.
    ///
    /// This was a live defect in both implementations. `reduce_to_base_word` filtered to
    /// `is_ascii_alphanumeric`, so a password written in Cyrillic, Han, Kana, Hangul, Greek,
    /// Arabic, Hebrew or Thai reduced to the empty string — below `MIN_BASE_LENGTH`, which
    /// `is_breached` answers `true` for. Every such user was refused on register, on reset and
    /// on change, and told their password was commonly used. The effect was to push a whole
    /// class of users onto the strictly smaller ASCII keyspace, which inverts the purpose of a
    /// breach screen. Neither suite caught it: both tested ASCII inputs only.
    #[tokio::test]
    async fn a_strong_non_latin_password_is_admitted() {
        let checker = CommonPasswordChecker::new();
        for password in [
            "пароль-очень-длинный",
            "日本語のパスワードです",
            "κωδικόςπρόσβασης",
            "비밀번호가아주깁니다",
            "סיסמאארוכהמאוד",
            "كلمةالمرورطويلةجدا",
            "ЖЫрафЖираф77",
            "Ünterwegs-2024",
        ] {
            assert!(
                !checker.is_breached(password).await,
                "{password} is strong and must be admitted"
            );
        }
    }

    /// The characters survive the reduction rather than merely being tolerated, which is what
    /// makes a consumer's non-Latin extra word reachable at all: extras are normalized through
    /// the same function, so under the ASCII filter every one of them became "".
    #[test]
    fn non_ascii_letters_survive_the_reduction() {
        assert_eq!(reduce_to_base_word("Пароль"), "пароль");
        assert_eq!(reduce_to_base_word("日本語"), "日本語");
        assert_eq!(reduce_to_base_word("Ünterwegs-2024"), "ünterwegs");
    }

    #[tokio::test]
    async fn a_non_latin_extra_word_matches() {
        let checker = CommonPasswordChecker::with_extra_words(["пароль"]);
        assert!(checker.is_breached("Пароль123").await);
        // A different Cyrillic word is still admitted — the entry blocks itself, not the script.
        assert!(!checker.is_breached("черепаха").await);
    }

    /// Widening what reduces to a non-empty base must not widen what gets through. Each of
    /// these is decoration around a fragment too short to be a word, which is what the length
    /// floor exists for.
    #[tokio::test]
    async fn the_weak_ascii_shapes_are_still_refused() {
        let checker = CommonPasswordChecker::new();
        for password in ["!!!!!!!!", "12345678", "a1234567", "abc12345"] {
            assert!(
                checker.is_breached(password).await,
                "{password} must be refused"
            );
        }
    }

    /// A repeated single character in a non-Latin script is now caught by the repeated-unit
    /// rule instead of by collapsing to "". Same answer, reached for the right reason — and the
    /// reason is what keeps holding when the script changes again.
    #[tokio::test]
    async fn a_repeated_non_ascii_character_is_refused_by_the_repetition_rule() {
        let checker = CommonPasswordChecker::new();
        assert!(checker.is_breached("аааааааа").await);
        assert!(checker.is_breached("東東東東東東東東").await);
    }
}
