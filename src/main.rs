extern crate cpals;

fn main() {
    #[derive(Debug)]
    struct TestCase {
        s: &'static str,
        i: i32,
    }
    
    let tc = TestCase{s: "foo", i: 10};
    println!("tc is {:?}", tc);
    //cpals::set1::challenge3();
}
