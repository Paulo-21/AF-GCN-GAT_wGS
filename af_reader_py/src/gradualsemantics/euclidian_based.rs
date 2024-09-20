use crate::graph::ArgumentationFramework;

const EPSILON : f64 = 0.0001;

pub fn solve(af : &ArgumentationFramework) -> Vec<f64> {
    let mut res: Vec<f64> = vec![1.0;af.nb_argument];
    let mut new_scores: Vec<f64> = vec![1.0;af.nb_argument];
    let mut has_changed = true;
	while has_changed {
		for (i, all_attacker) in af.af_attacker.iter().enumerate() {
			let mut sum_score_attacker = 0.;
			for  attacker in all_attacker {
				unsafe {
					sum_score_attacker += res.get_unchecked(*attacker as usize).powi(2);
				}
			}
			new_scores[i] =  1. / (1. + sum_score_attacker.sqrt());
		}
		if stabilisation(&new_scores, &res) {
			has_changed = false;
		}
        std::mem::swap(&mut res, &mut new_scores);
	}
	res
}

fn stabilisation(tab1 : &[f64], tab2 : &[f64]) -> bool {
	for (i, x) in tab1.iter().enumerate() {
		unsafe {
			if (x-tab2.get_unchecked(i)).abs() > EPSILON {
				return false;
			}
		}
	}
	true
}