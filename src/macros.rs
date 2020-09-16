/// utility: fill an array (only for test)
#[cfg(test)]
macro_rules! fill_vec {
    ($n: expr, $c: expr) => {
        (0..$n).map(|_| $c).collect::<Vec<_>>()
    };
}

/// utility: safe unwrap
///
/// If the expression contains an error, immediately return an error.
macro_rules! unwrap_safe {
    ($exp: expr) => {{
        match $exp {
            Ok(ans) => ans,
            Err(e) => {
                #[cfg(all(test, feature="std"))]
                {
                    algebra_core::println!(
                        "error: {} \n        at {:?}",
                        stringify!($exp),
                        file!().to_string() + ":" + &line!().to_string()
                    );
                }
                return Err(crate::Error::CausedBy(algebra_core::format!("{}", e)));
            }
        }
    }};
}

/// utility: safely extract value from Option (remove duplicate)
macro_rules! extract_safe {
    ($exp: expr) => {
        unwrap_safe!(
            $exp.ok_or(crate::Error::InternalDataStructureCorruption(Some(
                algebra_core::format!("{} is None", stringify!($exp))
            )))
        )
    };
}

/// utility: safely extract value from Option
macro_rules! assert_safe {
    ($exp: expr) => {{
        if !($exp) {
            return Err(crate::Error::InternalDataStructureCorruption(Some(
                algebra_core::format!("Assertion Failed: {} is false", stringify!($exp)),
            )));
        }
    }};
}

/// utility for benchmark: time the function
#[allow(unused_macros)]
#[cfg(all(test, feature="std"))]
macro_rules! timeit {
    ($exp:expr) => {{
        use std::time::Instant;
        let t0 = Instant::now();
        let ans = $exp;
        println!(
            "timeit: {}@{:?} takes {}ms",
            stringify!($exp),
            file!().to_string() + ":" + &line!().to_string(),
            (Instant::now() - t0).as_millis()
        );
        ans
    }};
    ($exp:expr, $des: expr) => {{
        use std::time::Instant;
        let t0 = Instant::now();
        let ans = $exp;
        println!(
            "timeit: {}@{:?} takes {}ms",
            $des,
            file!().to_string() + ":" + &line!().to_string(),
            (Instant::now() - t0).as_millis()
        );
        ans
    }};
}

/// only output timeit information in testing
#[allow(unused_macros)]
#[cfg(any(not(test), not(feature="std")))]
macro_rules! timeit {
    ($exp:expr) => {
        $exp
    };
    ($exp:expr, $des: expr) => {
        $exp
    };
}

#[cfg(test)]
macro_rules! random_gkr {
    ($rng: expr, $nv: expr, $gkr: ident) => {
        let f1: S;
        let f2_arr;
        let f2;
        let f3_arr;
        let f3;
        let $gkr;
        {
            use crate::data_structures::tests::random_sparse_poly_fast;
            use crate::data_structures::GKRAsLink;
            use algebra::UniformRand;
            f1 = random_sparse_poly_fast($nv * 3, $rng);
            f2_arr = fill_vec!(1 << $nv, F::rand($rng));
            f2 = D::from_slice(&f2_arr).unwrap();
            f3_arr = fill_vec!(1 << $nv, F::rand($rng));
            f3 = D::from_slice(&f3_arr).unwrap();
            $gkr = GKRAsLink::new(&f1, &f2, &f3).unwrap();
        }
    };
}
