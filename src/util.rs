use rand::Rng;

pub fn random_pos_i32() -> i32 {
    let mut rng = rand::thread_rng();

    rng.gen_range(0..=i32::MAX)
}
