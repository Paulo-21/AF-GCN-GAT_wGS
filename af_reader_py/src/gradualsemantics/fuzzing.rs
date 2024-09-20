//use std::time::Instant;
use crate::graph::ArgumentationFramework;
const EPSILON : f64 = 0.01;

pub fn solve(af : &ArgumentationFramework) -> Vec<f64> {
    let mut res = vec![1.;af.nb_argument];
    let mut new_scores = vec![1.;af.nb_argument];
    let mut k = 0;
	loop {
        for i in 0..af.nb_argument {
            let mut max_attacker = 0.;
            for attacker in &af.af_attacker[i] {
                if res[*attacker] > max_attacker {
                    max_attacker = res[*attacker];
                }
            }
            new_scores[i] = 0.5 * (res[i] + (1. - max_attacker));
        }
        std::mem::swap(&mut res, &mut new_scores);
        if stabilisation(&res, &new_scores) {
            return res;
        }
        if k > 400 {
            return res;
        }
        k+=1;
    }
}
fn stabilisation(tab1 : &[f64], tab2 : &[f64]) -> bool {
	for (i, x) in tab1.iter().enumerate() {
		if (x-tab2[i]).abs() > EPSILON {
			return false;
		}
	}
	true
}