use convert::*;
use rand::Rng;
use set3::*;

/*
 * Too slow to leave in
 *
use util::*;

#[test]
pub fn challenge24_b() {
    let token_length = 16;
    let test_cases = (0..20).map(|_| {
        let is_a_token = rand::thread_rng().gen();
        if is_a_token {
            (is_a_token, mt_make_password_token(token_length))
        } else {
            (is_a_token, get_random_bytes(token_length))
        }
    });

    for test_case in test_cases {
        let (actually_is_a_token, buf) = test_case;
        let detected_token = is_current_time_mt_token(&buf);
        assert_eq!(actually_is_a_token, detected_token);
    }
}
*/

#[test]
pub fn test_longest_common_substring() {
    let test_cases = [
        ("fooo", "poodle", "oo"),
        ("fooo", "pooodle", "ooo"),
        ("fooo", "badger", ""),
        ("foofoooofoo", "fooxfooooboo", "foooo"),
    ];

    for test_case in test_cases.iter() {
        let (xs, ys, expected_longest) = *test_case;
        let xs = &s2b(xs);
        let ys = &s2b(ys);
        let longest_ss = b2s(&longest_common_substring(xs, ys));
        assert_eq!(longest_ss, expected_longest);
    }
}

#[test]
pub fn test_slice_contains() {
    let test_cases = [
        ("fooo", "f", true),
        ("ooo", "f", false),
        ("furrfuu", "furr", true),
        ("furrfuu", "urrf", true),
        ("furrfuu", "fuu", true),
        ("furrfuu", "rrr", false),
        ("furrfuu", "uuu", false),
    ];

    for test_case in test_cases.iter() {
        let (xs, ys, expected_contains) = *test_case;
        let xs = s2b(xs);
        let ys = s2b(ys);
        let contains = slice_contains(&xs, &ys);
        assert_eq!(contains, expected_contains);
    }
}

#[test]
pub fn test_substring_finder() {
    //            let test_cases = [("foo", ["f", "fo", "foo", "o", "oo", "o"])];
    let test_cases = [("foo", ["foo", "fo", "oo", "f", "o", "o"])];
    for test_case in test_cases.iter() {
        let (s, ss) = *test_case;
        let s = &s2b(&s);
        let ss = ss.iter().map(|ss_str| s2b(ss_str));
        let finder = SubstringFinder::new(s);
        finder.for_each(|substr| println!("JB found {}", b2s(&substr)));
        let finder = SubstringFinder::new(s);
        assert!(finder.eq(ss));
    }
}

#[test]
pub fn test_mt_ctr() {
    let plain_text = &s2b("Wooodle booodle fluffetey buffetey");

    let random_seed: u16 = rand::thread_rng().gen();
    let cipher_text = &mt_ctr_cryptor(random_seed, &plain_text);
    assert_ne!(cipher_text, plain_text);

    let replain_text = &mt_ctr_cryptor(random_seed, &cipher_text);
    assert_eq!(plain_text, replain_text);
}

#[test]
pub fn test_challenge23_tempering() {
    let test_cases = (0..10).map(|_| rand::random::<u32>());
    let l = 18;
    let t = 15;
    let c = 0xEFC60000;

    let mt = MersenneTwister::new();

    for tc in test_cases {
        let y = tc ^ (tc >> l);
        let x = y ^ (y >> l);
        assert_eq!(x, tc);

        let y = tc ^ (tc << l);
        let x = y ^ (y << l);
        assert_eq!(x, tc);

        let y = tc ^ ((tc << t) & c);
        let x = y ^ ((y << t) & c);
        assert_eq!(x, tc);

        let y_tempered = mt.temper(tc);
        let y_untempered = mt.untemper(y_tempered);
        assert_eq!(y_untempered, tc);
    }
}

#[test]
pub fn test_challenge23() {
    let random_seed = rand::thread_rng().gen();
    let mut mt = MersenneTwister::new();
    mt.seed(random_seed);

    let mut cloned_mt = mt_clone(&mut mt);

    let count = 100;
    for _ in 0..count {
        let orig_num = mt.genrand_int32();
        let cloned_num = cloned_mt.genrand_int32();
        //                println!("orig {:x} cloned {:x}", orig_num, cloned_num);
        assert_eq!(orig_num, cloned_num, "orig and clone agree");
    }
}

#[test]
fn test_mt_seed() {
    let mut mt_a = MersenneTwister::new();
    mt_a.seed(19650218);
    let mut mt_b = MersenneTwister::new();
    mt_b.seed(19650218);
    let mut mt_x = MersenneTwister::new();
    mt_x.seed(1623577);

    let num_tests = 100;
    for _ in 0..num_tests {
        let a = mt_a.genrand_int32();
        let b = mt_b.genrand_int32();
        let x = mt_x.genrand_int32();
        assert_eq!(
            a,
            b,
            //                    format!("Same seed for iteration {} still the same", i)
        );
        assert_ne!(
            a,
            x,
            //                    format!("Diff seed for iteration {} still the same", i)
        );
    }
}
