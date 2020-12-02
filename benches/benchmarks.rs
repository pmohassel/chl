#[macro_use]
extern crate bencher;

use bencher::Bencher;
use rand_core::OsRng;

fn bench_setup(b: &mut Bencher) {
    let mut rng = OsRng;
    b.iter(|| chl::setup(&mut rng));
}

fn bench_register(b: &mut Bencher) {
    let mut rng = OsRng;
    let (_pp, sk) = chl::setup(&mut rng);
    b.iter(|| chl::register(sk, b"username", b"password"));
}

fn bench_client_login(b: &mut Bencher) {
    let mut rng = OsRng;
    let (pp, _sk) = chl::setup(&mut rng);
    b.iter(|| chl::client_login(&pp, b"ssid", b"tok", b"username", b"password", &mut rng));
}

fn bench_server_login(b: &mut Bencher) {
    let mut rng = OsRng;
    let (pp, sk) = chl::setup(&mut rng);
    let password_file = chl::register(sk, b"username", b"password");
    let alpha = chl::client_login(&pp, b"ssid", b"tok", b"username", b"password", &mut rng);
    b.iter(|| chl::server_login(&pp, b"ssid", &password_file, &alpha));
}

benchmark_group!(
    benches,
    bench_setup,
    bench_register,
    bench_client_login,
    bench_server_login,
);
benchmark_main!(benches);
